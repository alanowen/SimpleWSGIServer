import sys
import select
import socket


class WSGIServer:
    def __init__(self, address='127.0.0.1', port=8080):
        self.address = address
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, port))
        self.sock.listen(128)

    def run(self):
        print('Server is running on (%s:%d).' % self.sock.getsockname())
        while True:
            conn, addr = self.sock.accept()
            print('Connected by (%s:%d).' % addr)
            with conn:
                data = b''
                while True:
                    d = conn.recv(1024)
                    if not d:
                        break
                    else:
                        data += d
                print(data.decode('utf-8'))


if __name__ == '__main__':
    server = WSGIServer()
    server.run()
