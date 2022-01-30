import sys
import socket
import threading

# We create a HEXFILTER string that contains ASCII printable characters, if one exists, or a dot (.)
# if such a representation does not exist.
HEX_FILTER = ''.join([(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])


# we define a hexdump function that takes some input as bytes or a string  and prints a hexdump to the console
def hexdump(src, length=16, show=True):
    # First, we make sure we have a string, decoding the bytes if a byte string was passed in
    # Then we grab a piece of the string to dump and put it into the word variable
    if isinstance(src, bytes):
        src = src.decode()

    results = list()
    for i in range(0, len(src), length):
        # We use the translate built-in function to substitute the string
        # representation of each character for the corresponding character in the raw
        # string (printable)
        word = str(src[i:i+length])

        # Likewise, we substitute the hex representation of the integer value of every character in the raw
        # string (hexa). Finally, we create a new array to hold the strings, result, that contains
        # the hex value of the index of the first byte in the word, the hex value of the word,
        # and its printable representation
        printable = word.translate(HEX_FILTER)
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length * 3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
    if show:
        for line in results:
            print(line)
    else:
        return results


def receive_from(connection):
    buffer = b""
    # We create an empty byte string, buffer, that will accumulate
    # responses from the socket
    connection.settimeout(5)
    try:
        while True:
            # By default, we set a five-second time-out, which might be aggressive if you’re proxying traffic
            # to other countries or over lossy networks, so increase the time-out as necessary.
            # We set up a loop to read response data into the buffer
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    return buffer


# Inside these functions, you can modify the packet contents, perform
# fuzzing tasks, test for authentication issues, or do whatever else your heart
# desires. This can be useful, for example, if you find plaintext user credentials
# being sent and want to try to elevate privileges on an application by
# passing in admin instead of your own username.
def request_handler(buffer):
    # perform packet modifications
    return buffer


def response_handler(buffer):
    # perform packet modifications
    return buffer


# This function contains the bulk of the logic for our proxy. To start off,
# we connect to the remote host
def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    # Then we check to make sure we don’t need to first initiate a connection to the remote side and request data
    # before going into the main loop. Some server daemons will expect you to do this
    # (FTP servers typically send a banner first, for example).
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

    # We then use the receive_from function for both sides of the communication.It accepts a connected socket
    # object and performs a 'receive'. We dump the contents of the packet so that we can inspect it for anything
    # interesting. Next, we hand the output to the response_handler function and then send the received buffer
    # to the local client.
    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
        client_socket.send(remote_buffer)

    # The rest of the proxy code is straightforward: we set up our loop to continually read from the local client,
    # process the data, send it to the remote client, read from the remote client, process the data, and send it
    # to the local client until we no longer detect any data. When there’s no data to send on either side of the
    # connection, we close both the local and remote sockets and break out of the loop.
    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            line = "[<==] Sending %d bytes to localhost." % len(local_buffer)
            print(line)
            hexdump(local_buffer)

            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)

        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break


def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # The server_loop function creates a socket 1 and then binds to the local
        # host and listens
        server.bind((local_host, local_port))  # bind
    except Exception as e:
        print('problem on bind: %r' % e)

        print("[!!] Failed to listen on %s %d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    print("[*] Listening on %s %d" % (local_host, local_port))
    server.listen(5)  # listen

    # In the main loop, when a fresh connection request comes in, we hand it off to the proxy_handler in a new thread.
    # Which performs all the sending and receiving of juicy bits to either side of the data stream.
    while True:
        client_socket, addr = server.accept()
        # print the local server information
        line = "> Received incoming connection from %s %d" % (addr[0], addr[1])
        print(line)
        # start a thread to talk to the remote host
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host,
                  remote_port, receive_first))
        proxy_thread.start()


def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./tcp_proxy.py [localhost] [localport]", end='')
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./tcp_proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    reveive_first = sys.argv[5]

    if "True" in reveive_first:
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)


if __name__ == '__main__':
    main()
