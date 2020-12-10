
# THIS IS WHERE SECRET CODE
# Unicorn1989

import socket

HOST = '127.0.0.1' # Standard loopback interface address (localhost)
PORT = 65432 # Port that our server will listen on (non-priileged ports > 1023)

# In what order will we need to make API calls for socket API

# 1. Create a socket with socket()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    # 2. Bind the socket to an IP address and port with bind()
    s.bind((HOST, PORT))

    # 3. Listen for incoming connections with listen()
    s.listen()

    # 4. Accept an incoming connection wtih accept()
    conn, addr = s.accept()
    with conn:
        print('Connected to client: %d', addr)

        while True:

            # 5. Receive incoming data with recv()
            data = conn.recv(1024)
            if not data: 
                break
            # 6. Send data back to client
            conn.sendall(data)

