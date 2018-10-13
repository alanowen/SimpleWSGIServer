# import io
import os
import re
import abc
import cgi
# import sys
import uuid
import gzip
# import time
import base64
# import ctypes
# import random
import doctest
import inspect
# import hashlib
import logging
# import binascii
# import datetime
import mimetypes
import functools
from urllib.parse import quote, unquote
# import importlib
# import itertools
import traceback
from threading import local
from wsgiref.simple_server import make_server
from collections import OrderedDict

from jinja2 import Environment, PackageLoader, select_autoescape


ctx = local()


RESPONSE_STATUS = {
    # 100 ~ 199 Info status
    100: 'Continue',
    101: 'Switching Protocols',

    # 200 ~ 299 Success status
    200: 'OK',
    201: 'Created',
    202: 'Accepted',
    203: 'Non-Authoritive Information',
    204: 'No Content',
    205: 'Reset Content',
    206: 'Partial Content',

    # 300 ~ 399 Redirect status
    300: 'Multiple Choices',
    301: 'Moved Permanently',
    302: 'Found',
    303: 'See Other',
    304: 'Not Modified',
    305: 'Use Proxy',
    307: 'Temporary Redirect',

    # 400 ~ 499 Client error status
    400: 'Bad Request',
    401: 'Unauthorized',
    402: 'Payment Required',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    406: 'Not Acceptable',
    407: 'Proxy Authentication Required',
    408: 'Request Timeout',
    409: 'Conflict',
    410: 'Gone',
    411: 'Length Required',
    412: 'Precondition Failed',
    413: 'Request Entity Too Large',
    414: 'Request URI Too Long',
    415: 'Unsupported Media Type',
    416: 'Request Range Not Satisfiable',
    417: 'Expectation Failed',

    # 500 ~ 599 Server error status
    500: 'Internal Server Error',
    501: 'Not Implemented',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
    505: 'HTTP Version Not Supported'
}


class CaseInsensitiveDict(dict):
    """
    >>> data = {'key1': 'value1', 'key2': 'value2'}

    >>> d = CaseInsensitiveDict(data)

    >>> d['Key1']
    'value1'

    >>> d['key1']
    'value1'

    >>> d['key2']
    'value2'

    >>> d['Key2']
    'value2'
    """

    def __init__(self, data):
        self.proxy = dict((key.lower(), key) for key in data)
        super(CaseInsensitiveDict, self).__init__(**data)

    def __contains__(self, key):
        return key.lower() in self.proxy

    def __delitem__(self, key):
        k = self.proxy[key.lower()]
        super(CaseInsensitiveDict, self).__delitem__(k)
        del self.proxy[key.lower()]

    def __getitem__(self, key):
        k = self.proxy[key.lower()]
        return super(CaseInsensitiveDict, self).__getitem__(k)

    def get(self, key, default=None):
        return self[key] if key in self else default

    def __setitem__(self, key, value):
        super(CaseInsensitiveDict, self).__setitem__(key, value)
        self.proxy[key.lower()] = key


class HttpError(Exception):

    def __init__(self, code):
        super(Exception, self).__init__()
        self.code = code

    @property
    def status(self):
        return get_response_status(self.code)

    @property
    def headers(self):
        return []

    def __repr__(self):
        return self.status

    def __str__(self):
        return self.status


class HttpBadRequest(HttpError):

    def __init__(self):
        super(HttpBadRequest, self).__init__(400)


class HttpUnauthorized(HttpError):

    def __init__(self):
        super(HttpUnauthorized, self).__init__(401)


class HttpForbidden(HttpError):

    def __init__(self):
        super(HttpForbidden, self).__init__(403)


class HttpNotFound(HttpError):

    def __init__(self):
        super(HttpNotFound, self).__init__(404)


class HttpMethodNotAllowed(HttpError):

    def __init__(self):
        super(HttpMethodNotAllowed, self).__init__(405)


class HttpRedirect(HttpError):

    def location(self, url):
        pass


def get_response_status(code):
    return '%d %s' % (code, RESPONSE_STATUS[code])


class Router:

    def __init__(self):
        self.routes = [StaticRoute()]

    def __call__(self, url_path, method):
        for route in self.routes:
            matched = route.match(url_path)
            if matched[0]:
                if route.method == method:
                    if len(route.path_variables) > 0:
                        result = route.func(*matched[1])
                    else:
                        result = route.func()
                    return make_response(result)
                else:
                    raise HttpMethodNotAllowed()
        else:
            raise HttpNotFound()

    def add_route(self, route):
        self.routes.append(route)


class Route(metaclass=abc.ABCMeta):

    def match(self, url_path):
        m = self.path_regex.match(url_path)
        if m:
            return True, m.groups()
        else:
            return (False,)

    def check_route_params(self, variables):
        sig = inspect.signature(self.func)
        assert len(variables) == len(sig.parameters.keys()), 'route parameters not matched'

        for i in zip(variables, sig.parameters):
            assert i[0] == i[1], 'route parameters not matched'

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.path_regex)


class ViewRoute(Route):

    def __init__(self, url_path, method, func):
        self.method = method
        self.func = func
        self.path_regex, self.path_variables = self.build_path_components(url_path)

        self.check_route_params(self.path_variables)

    def build_path_components(self, url_path):
        """
        # /path/path2/path3/<num1>
        # ^/path/path2/path3/(?P<num1>[^\\/]+)$

        # /path/<num1>/path3/<num2>
        # ^/path/(?P<num1>[^\\/]+)/path3/(?P<num2>[^\\/]+)$
        # buf = ctypes.create_unicode_buffer(url_path)
        """
        r = re.compile(r'(<[a-zA-Z_]\w*>)')

        path_variables = []
        path_components = ['^']

        for item in r.split(url_path):
            if r.match(item):
                path_variables.append(item[1:-1])
                path_components.append(r'(?P<%s>[^\\/]+)' % item[1:-2])
            else:
                if item != '':
                    path_components.append(item)
        path_components.append('$')

        return re.compile(''.join(path_components)), path_variables


class StaticRoute(Route):

    def __init__(self):
        self.path_regex = re.compile(r'^/static/(?P<file_path>.+)$')
        self.path_variables = ['file_path']
        self.method = 'GET'
        self.check_route_params(self.path_variables)

    def func(self, file_path):
        def read_file(path, buff_size=8192):
            with open(path, 'rb') as f:
                chunk = f.read(buff_size)
                while chunk:
                    yield chunk
                    chunk = f.read(buff_size)

        file_path = os.path.join(ctx.current_app.static_path, file_path)

        if not os.path.exists(file_path):
            raise HttpNotFound()

        file_ext = os.path.splitext(file_path)[1]

        ctx.response.content_type = mimetypes.types_map.get(file_ext, 'application/octet-stream')
        return b''.join(read_file(file_path))


class HttpRequest:

    def __init__(self, environ):
        self.environ = environ
        # get form data
        form = cgi.FieldStorage(fp=self.environ['wsgi.input'], environ=self.environ, keep_blank_values=True)
        for i in environ:
            print('%s: %s' % (i, environ[i]))
            CONTENT_TYPE: text/plain
            # HTTP_HOST: 127.0.0.1:8080
            # HTTP_CONNECTION: keep-alive
            # HTTP_PRAGMA: no-cache
            # HTTP_CACHE_CONTROL: no-cache
            # HTTP_UPGRADE_INSECURE_REQUESTS: 1
            # HTTP_USER_AGENT: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) snap Chromium/69.0.3497.100 Chrome/69.0.3497.100 Safari/537.36
            # HTTP_ACCEPT: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
            # HTTP_ACCEPT_ENCODING: gzip, deflate, br
            # HTTP_ACCEPT_LANGUAGE: en-US,en;q=0.9
            # HTTP_COOKIE: index=hello; index1=hello1

    def parse_input(self):
        pass

    @property
    def request_method(self):
        return self.environ['REQUEST_METHOD']

    @property
    def headers(self):
        pass

    @property
    def path_info(self):
        return self.environ['PATH_INFO']

    @property
    def accept_encoding(self):
        return self.environ['HTTP_ACCEPT_ENCODING']

    @property
    def session(self):
        return {}

    @property
    def cookie(self):
        return ''


class HttpResponseBody:

    def __get__(self, obj, cls):
        return obj.__dict__.get('__body__', [])

    def __set__(self, obj, value):
        # if obj.use_gzip:
        #     obj.__dict__['__body__'] = [gzip.compress(b''.join(value))]
        #     obj.content_length = obj.__dict__['__body__']
        # else:
        #     obj.__dict__['__body__'] = value
        #     obj.content_length = sum(len(i) for i in value)
        if not isinstance(value, [list, tuple]):
            value = [value]
        obj.__dict__['__body__'] = value
        obj.content_length = sum(len(i) for i in value)


class HttpResponse:

    def __init__(self, use_gzip=False, content=None, code=200):
        self.code = code
        self.header_dict = CaseInsensitiveDict(OrderedDict([]))
        self.use_gzip = use_gzip
        self.content = HttpResponseBody()
        self.cookie = OrderedDict()

    @property
    def status(self):
        return get_response_status(self.code)

    @property
    def headers(self):
        if self.use_gzip:
            self.add_header('Content-Encoding', 'gzip')
        h = [(key, str(value)) for key, value in self.header_dict.items()]
        for k in self.cookie:
            h.append(('Set-Cookie', self.cookie[k]))
        return h

    def add_header(self, name, value):
        self.header_dict[name.title()] = str(value)

    @property
    def content_length(self):
        return self.header_dict.get('Conent-Length')

    @content_length.setter
    def content_length(self, value):
        self.add_header('Content-Length', value)

    @property
    def content_type(self):
        return self.header_dict.get('Content-Type')

    @content_type.setter
    def content_type(self, value):
        self.header_dict['Content-Type'] = value

    def set_cookie(self, name, value, expires=None, max_age=60 * 60, path='/', domain=None, http_only=True, secure=False):
        v = ['%s=%s' % (quote(name), quote(value))]
        if not expires:
            pass
        if not max_age:
            pass
        v.append('Path=%s' % path)
        if not domain:
            pass
        if http_only:
            v.append('HttpOnly')
        if not secure:
            pass
        self.cookie[name] = '; '.join(v)


def make_response(*data, code=200):
    content = []
    response = ctx.response

    for item in data:
        if isinstance(item, str):
            content.append(item.encode('utf-8'))
        elif isinstance(item, bytes):
            content.append(item)
        else:
            raise TypeError('response content type error')
    if content:
        response.content = content
    if not response.content_type:
        # set default content-type
        response.content_type = 'text/plain'
    response.code = code
    return response


def redirect():
    pass


class TemplateEngine:

    def __init__(self):
        pass

    env = Environment(
        loader=PackageLoader('__main__', 'templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )


class Wispy:

    def __init__(self, static_name='static', static_path=None, template_path=None, *args, **kwargs):
        self.root_path = os.path.abspath(os.path.dirname(__file__))

        if not static_path:
            self.static_path = os.path.join(self.root_path, 'static')

        if not template_path:
            self.template_path = os.path.join(self.root_path, 'templates')

        self.static_name = static_name

        self.before_interceptors = []
        self.after_interceptors = []

        self.router = Router()

        self.templage_engine = Environment(
                loader=PackageLoader('__main__', 'templates'),
                autoescape=select_autoescape(['html', 'xml']))

    def get(self, url_path):
        def decorated(func):
            route = ViewRoute(url_path, 'GET', func)
            self.router.add_route(route)
            return func
        return decorated

    def post(self, url_path):
        def decorated(func):
            route = ViewRoute(url_path, 'POST', func)
            self.router.add_route(route)
            return func
        return decorated

    def options(self, url_path):
        def decorated(func):
            route = ViewRoute(url_path, 'OPTIONS', func)
            self.router.add_route(route)
            return func
        return decorated

    def head(self, url_path):
        def decorated(func):
            route = ViewRoute(url_path, 'HEAD', func)
            self.router.add_route(route)
            return func
        return decorated

    def view(self, template_name):
        def wrapper(func):
            @functools.wraps(func)
            def decorated(*args, **kwargs):
                ctx.response.content_type = 'text/html'
                template = self.templage_engine.get_template(template_name)
                return template.render(**func(*args, **kwargs))
            return decorated
        return wrapper

    def before_request(self, func):
        self.before_interceptors.append(func)
        return func

    def after_request(self, func):
        self.after_interceptors.append(func)
        return func

    def run(self, host, port, debug=False):

        if debug is True:
            setattr(self, 'debug', True)

        server = make_server(host=host, port=port, app=self)
        server.serve_forever()

    def process_request(self):
        self.router(ctx.request.path_info, ctx.request.request_method)

    def __call__(self, environ, start_response):

        ctx.request = HttpRequest(environ)
        ctx.response = HttpResponse()
        ctx.current_app = self

        try:
            # for item in self.before_request:
            #     pass

            self.process_request()
            # for item in self.after_request:
            #     pass
            start_response(ctx.response.status, ctx.response.headers)

            # return end_response(response)
            return ctx.response.content
        except HttpError as e:
            start_response(e.status, e.headers)
            return [e.status.encode('utf-8')]
        except Exception as e:
            if getattr(self, 'debug', False) is True:
                traceback.print_exc()
            else:
                logging.exception(e)
            status = get_response_status(500)
            start_response(status, [])
            return [status.encode('utf-8')]
        finally:
            del ctx.request
            del ctx.response
            del ctx.current_app


if __name__ == '__main__':

    app = Wispy()

    @app.get('/')
    def index():
        ctx.response.set_cookie('index', 'hello')
        ctx.response.set_cookie('index1', 'hello1')
        return 'hello'

    @app.get('/index/<name>/<username>')
    @app.view('index.html')
    def test(name, username):
        return dict(username=username)

    @app.get('/home')
    def home():
        return make_response('home')

    doctest.testmod()

    app.run(host='localhost', port=8080, debug=True)
