#! /user/bin/env python
# coding=utf-8

import re


class Application(object):

    def __init__(self, urls):
        self.urls = urls

    def __call__(self, environ, start_response):
        method = environ['REQUEST_METHOD']
        path = environ['PATH_INFO']
        for pattern, name in self.urls:
            p = re.compile('^' + pattern + '$')
            m = re.match(p, path)
            if m:
                args = m.groups()
                funcName = method.Upper() + '_' + name
                func = getattr(self, funcName)
                return func(*args)
            return self.not_found(start_response)

    def not_found(self, start_response):
        status = '404 Not Found'
        response_header = [('Content-type', 'text/plain')]
        start_response(status, response_header)
        yield 'Page Not Found'


if __name__ == '__main__':
    from server import Whisky
    urls = [('/', 'index')]
    app = Application(urls)
    server = Whisky(('localhost', 8080))
    server.set_application(app)
    server.serve_forever()
