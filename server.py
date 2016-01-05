#! /user/bin/env python
# coding=utf-8

import socket
import StringIO
import sys


class Whisky(object):

    def __init__(self, server_address):
        self._listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_socket.setsockopt(socket.SOL_SOCKET,
                                       socket.SO_REUSEADDR, 1)
        self._listen_socket.bind(server_address)

        host, port = self._listen_socket.getsockname()[:2]
        self._listen_socket.listen(10)
        self.server_name = socket.getfqdn(host)
        self.server_port = port

    def set_application(self, application):
        self.application = application

    def get_environ(self):
        env = dict()
        # WSGI
        env['wsgi.version'] = (1, 0)
        env['wsgi.url_csheme'] = 'http'
        env['wsgi.input'] = StringIO.input
        env['wsgi.errors'] = sys.stderr
        env['wsgi.multithread'] = False
        env['wsgi.run_once'] = False
        # CGI
        env['METHOD'] = self.request.method
        env['PATH_INFO'] = self.path
        env['SERVERNAME_NAME'] = self.server_name
        env['SERVERPATH_PORT'] = str(self.server_port)

    def handle_one_request(self, client_socket):
        request_data = client_socket.recv(1024)
        for line in request_data.splitlines():
            print '>>%s' % line
        self.request = Request(request_data)

    def serve_forever(self):
        try:
            while True:
                client_socket, client_address = self._listen_socket.accept()
                print 'Client connected! Connection: %s, Address: %s\n' \
                    % (client_socket, client_address)
                self.handle_one_request(client_socket)
        except Exception as e:
            raise e


class Request(object):

    def __init__(self, data):
        pass


if __name__ == '__main__':
    if sys.argv.count < 2:
        sys.exit('')
        application_path = sys.arg[1]
        module, application = application_path.split[':']
        module = __import__(module)
        application = getattr(module, application)
        server = Whisky(('127.0.0.1', 8080), None)
        server.serve_forever()
    else:
        import ipdb; ipdb.set_trace()  # XXX BREAKPOINT
        server = Whisky(('127.0.0.1', 8080))
        server.serve_forever()
