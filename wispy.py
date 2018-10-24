from os import path as os_path
import re
import abc
import cgi
import sys
import uuid
import gzip
import time
import base64
import ctypes
import random
import doctest
import inspect
import hashlib
import logging
import builtins
import binascii
import datetime
import mimetypes
import functools
from urllib.parse import quote as url_quote, unquote as url_unquote
import importlib
import itertools
import traceback
from threading import local
from wsgiref.simple_server import make_server
from collections import OrderedDict, namedtuple

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


def to_bytes(s):
    return s.encode('utf-8')


def to_str(b):
    return b.decode('ascii')


def read_file(file_path, buff_size=8192):
    with open(file_path, 'rb') as f:
        chunk = f.read(buff_size)
        while chunk:
            yield chunk
            chunk = f.read(buff_size)


class UTC:
    pass


class CaseInsensitiveDict(dict):

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
        self.headers = []

    @property
    def status(self):
        return get_response_status(self.code)

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

    def __init__(self, code, location):
        super(HttpRedirect, self).__init__(code)
        self.location = location
        self.headers = [('Location', location)]


def get_response_status(code):
    return '%d %s' % (code, RESPONSE_STATUS[code])


class Delegate:

    def __init__(self, callable_obj=None):
        if not callable(callable_obj):
            raise ValueError('%s is not callable' % callable_obj.__name__)
        self.funcs = [callable_obj] if callable_obj else []
        self.result = []

    def __get__(self, obj, cls):
        return self

    def __set__(self, obj, callable_obj):
        if callable_obj is not self:
            if not callable(callable_obj):
                raise ValueError('%s is not callable' % callable_obj.__name__)
            else:
                self.funcs = [callable_obj]

    def __call__(self):
        for callable_obj in self.funcs:
            self.result.append(callable_obj())
        return self.result

    def __iadd__(self, callable_obj):
        self.funcs.append(callable_obj)
        return self

    def __isub__(self, callable_obj):
        i = self.funcs.index(callable_obj)
        if i > 0:
            self.funcs.pop(i)
        return self


class RouteParameter(namedtuple('RouteParameter', ['name', 'type', 'value'])):
    __slots__ = ()

    def replace_value(self, value):
        return self._replace(value=value)

    def __repr__(self):
        return '<RouteParameter %s %s %s>' % (self.name, str(self.value), self.type)

    def convert_value(self):
        return getattr(builtins, self.type)(self.value)


# make None as default value to RouteParameter
RouteParameter.__new__.__defaults__ = (None,) * len(RouteParameter._fields)


class Router:

    def __init__(self):
        self.routes = []
        self.route_filter = {
            'str': '[^\\/]+',
            'int': '[-+]?[\d]+',
            'float': '[-+]?\d*\.\d+|\d+'
        }
        self.param_pattern = re.compile('(<(?:(?:int:)|(?:str:)|(?:float:))?[a-zA-Z_]\w*>)')

    def __call__(self, url_path, method):
        for route in self.routes:
            matched = route.match(url_path)
            if matched:
                if route.method == method:
                    if len(route.route_param_dict) > 0:
                        result = route.callback(**route.get_converted_value_dict())
                    else:
                        result = route.callback()
                    return make_response(result)
                else:
                    raise HttpMethodNotAllowed()
        else:
            raise HttpNotFound()

    def add_view_route(self, url_path, method, callback):
        route_regex, route_param_dict = self.build(url_path)
        self.check_route_params(route_param_dict, callback)
        route = ViewRoute(url_path, method, callback, route_regex, route_param_dict)
        self.routes.append(route)

    def check_route_params(self, route_param_dict, callback):
        # get signature obj of the callback obj
        sig = inspect.signature(callback)
        if route_param_dict.keys() != sig.parameters.keys():
            raise RouteBuildException('route parameters not matched')

    def build(self, url_path):
        param_dict = OrderedDict()
        pattern = ['^']

        for item in self.param_pattern.split(url_path):
            if self.param_pattern.match(item):
                if ':' not in item:
                    item = '<str:' + item[1:]
                v_type, v_name = item[1:-1].split(':')
                param = RouteParameter(name=v_name, type=v_type, value=None)
                param_dict[v_name] = param
                pattern.append('(?P<%s>%s)' % (param.name, self.route_filter[param.type]))
            else:
                if item != '':
                    pattern.append(item)
        pattern.append('$')
        return re.compile(''.join(pattern)), param_dict


class Route:

    def __init__(self, url_path, method, callback, route_regex, route_param_dict):
        self.url_path = url_path
        self.method = method
        self.callback = callback
        self.route_regex = route_regex
        self.route_param_dict = route_param_dict

    def match(self, url_path):
        m = self.route_regex.match(url_path)
        if m:
            # set value to route param according route param type
            value_dict = m.groupdict()

            for name, param_obj in self.route_param_dict.items():
                value = value_dict[name]
                self.route_param_dict[name] = param_obj.replace_value(value)
            return True
        else:
            return False

    def get_converted_value_dict(self):
        return {name: obj.convert_value() for name, obj in self.route_param_dict.items()}

    def get_raw_value_dict(self):
        return {name: obj.value for name, obj in self.route_param_dict.item()}

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.route_regex)


class ViewRoute(Route):

    def __init__(self, url_path, method, callback, route_regex, route_param_dict):
        super(ViewRoute, self).__init__(url_path, method, callback, route_regex, route_param_dict)


class StaticRoute(Route):

    def __init__(self, url_path, method, callback, route_regex, route_param_dict):
        super(StaticRoute, self).__init__(url_path, method, callback, route_regex, route_param_dict)

    def build(self, url_path):
        return re.compile('^/static/(?P<file_path>.+)$'), ['file_path']


def send_static_file(file_path):
    file_path = os_path.join(ctx.current_app.static_path, file_path)

    if not os_path.exists(file_path):
        raise HttpNotFound()

    file_ext = os_path.splitext(file_path)[1]

    ctx.response.content_type = mimetypes.types_map.get(file_ext, 'application/octet-stream')
    return b''.join(read_file(file_path))


class HeaderDescriptor:
    """
    http header descriptor
    """

    def __init__(self, readonly=False, as_interface=False):
        self.readonly = readonly
        self.as_interface = as_interface

    def __get__(self, obj, cls):
        name = self.func.__name__.strip('_').upper()
        if isinstance(obj.injected, HttpRequest):
            return obj.injected.__dict__ \
                .setdefault('__headers__', {}) \
                .setdefault(name, obj.injected.environ.get('HTTP_%s' % name))
        elif isinstance(obj.injected, HttpResponse):
            if self.as_interface:
                return obj.injected.__dict__ \
                    .setdefault('__headers__', {}) \
                    .setdefault(name, obj.injected.environ.get('HTTP_%s' % name))
            else:
                return obj.injected.__dict__ \
                    .setdefault('__headers__', {}) \
                    .setdefault(name, obj.injected.environ.get('HTTP_%s' % name))
        else:
            raise TypeError('The type of object injected into HeaderDescriptor should be HttpResponse or HttpRequest.')

    def __set__(self, obj, value):
        if self.readonly:
            raise AttributeError('The %s is readonly' % self.__name__)

    def __call__(self, func):
        """
        This function is only used for wrapping function, it should not be called directly.
        :param func:
        :return:
        """
        self.func = func
        return self


class HttpGeneralHeaders:
    """
    http general headers
    """

    @HeaderDescriptor()
    def cache_control(self):
        pass

    @HeaderDescriptor()
    def content(self):
        pass

    @HeaderDescriptor()
    def _date(self):
        pass

    @HeaderDescriptor()
    def pragma(self):
        pass

    @HeaderDescriptor()
    def trailer(self):
        pass

    @HeaderDescriptor()
    def transfer_encoding(self):
        pass

    @HeaderDescriptor()
    def upgrade(self):
        pass

    @HeaderDescriptor()
    def via(self):
        pass

    @HeaderDescriptor()
    def warning(self):
        pass


class HttpEntityHeaders:

    @HeaderDescriptor()
    def allow(self):
        pass

    @HeaderDescriptor()
    def content_encoding(self):
        pass

    @HeaderDescriptor()
    def content_language(self):
        pass

    @HeaderDescriptor()
    def content_length(self):
        pass

    @HeaderDescriptor()
    def content_location(self):
        pass

    @HeaderDescriptor()
    def content_md5(self):
        pass

    @HeaderDescriptor()
    def content_range(self):
        pass

    @HeaderDescriptor()
    def content_type(self):
        pass

    @HeaderDescriptor()
    def expires(self):
        pass

    @HeaderDescriptor()
    def last_modified(self):
        pass


class HttpCookieHeaders:

    @HeaderDescriptor()
    def set_cookie(self):
        pass

    @HeaderDescriptor()
    def cookie(self):
        pass


class OtherHttpHeaders:
    pass


class HttpResponseHeaders(HttpGeneralHeaders):
    """
    http response headers
    """

    def __init__(self, injected):
        self.injected = injected

    # for i in environ:
    # print('%s: %s' % (i, environ[i]))
    # CONTENT_TYPE: text/plain
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

    @HeaderDescriptor()
    def accept_ranges(self):
        pass

    @HeaderDescriptor()
    def age(self):
        pass

    @HeaderDescriptor()
    def etag(self):
        pass

    @HeaderDescriptor()
    def location(self):
        pass

    @HeaderDescriptor()
    def proxy_authenticate(self):
        pass

    @HeaderDescriptor()
    def retry_after(self):
        pass

    @HeaderDescriptor()
    def server(self):
        pass

    @HeaderDescriptor()
    def vary(self):
        pass

    @HeaderDescriptor()
    def www_authenticate(self):
        pass


class HttpRequestHeaders(HttpGeneralHeaders):
    """
    http request headers
    """
    HeadDesc = functools.partial(HeaderDescriptor, readonly=True, as_interface=True)

    def __init__(self, injected):
        self.injected = injected

    @HeadDesc()
    def accept(self):
        pass

    @HeadDesc()
    def accept_charset(self):
        pass

    @HeadDesc()
    def accept_encoding(self):
        pass

    @HeadDesc()
    def accept_language(self):
        pass

    @HeadDesc()
    def authorization(self):
        pass

    @HeadDesc()
    def expect(self):
        pass

    @HeadDesc()
    def _from(self):
        pass

    @HeadDesc()
    def host(self):
        pass

    @HeadDesc()
    def if_match(self):
        pass

    @HeadDesc()
    def if_modified_since(self):
        pass

    @HeadDesc()
    def if_none_match(self):
        pass

    @HeadDesc()
    def if_range(self):
        pass

    @HeadDesc()
    def if_unmodified_since(self):
        pass

    @HeadDesc()
    def max_forwards(self):
        pass

    @HeadDesc()
    def proxy_authorization(self):
        pass

    @HeadDesc()
    def range(self):
        pass

    @HeadDesc()
    def referer(self):
        pass

    @HeadDesc()
    def te(self):
        pass

    @HeadDesc()
    def user_agent(self):
        pass
        # SERVER_PORT: 8080
        # REMOTE_HOST: 
        # CONTENT_LENGTH: 
        # SCRIPT_NAME: 
        # SERVER_PROTOCOL: HTTP/1.1
        # SERVER_SOFTWARE: WSGIServer/0.2
        # REQUEST_METHOD: GET
        # PATH_INFO: /
        # QUERY_STRING: 
        # REMOTE_ADDR: 127.0.0.1
        # CONTENT_TYPE: text/plain
        # HTTP_HOST: 127.0.0.1:8080
        # HTTP_CONNECTION: keep-alive
        # HTTP_CACHE_CONTROL: max-age=0
        # HTTP_UPGRADE_INSECURE_REQUESTS: 1
        # HTTP_USER_AGENT: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.67 Safari/537.36
        # HTTP_ACCEPT: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
        # HTTP_ACCEPT_ENCODING: gzip, deflate, br
        # HTTP_ACCEPT_LANGUAGE: en-US,en;q=0.9
        # HTTP_COOKIE: index=hello; index1=hello1


class HttpRequest:

    def __init__(self, environ):
        self.environ = environ
        # get form data
        # self.form = cgi.FieldStorage(fp=self.environ['wsgi.input'], environ=self.environ, keep_blank_values=True)
        self.headers = HttpRequestHeaders(self)

    @property
    def request_method(self):
        return self.environ['REQUEST_METHOD']

    @property
    def path_info(self):
        return url_unquote(self.environ['PATH_INFO'])

    @property
    def session(self):
        return {}

    def parse_input(self):
        pass


class HttpResponseBody:

    def __get__(self, obj, cls):
        return obj.__dict__.get('__body__', [])

    def __set__(self, obj, value):
        if not isinstance(value, (list, tuple)):
            value = [value]
        obj.__dict__['__body__'] = value
        obj.content_length = sum(len(i) for i in value)


class HttpResponse:

    def __init__(self, code=200):
        self.code = code
        self.header_dict = CaseInsensitiveDict(OrderedDict([]))
        self.content = HttpResponseBody()
        self.cookie = OrderedDict()
        self.headers = HttpResponseHeaders(self)

    @property
    def status(self):
        return get_response_status(self.code)

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

    def set_cookie(self, name, value, expires=None, max_age=60 * 60, path='/', domain=None, http_only=True,
                   secure=False):
        v = ['%s=%s' % (url_quote(name), url_quote(value))]
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
    contents = []
    response = ctx.response

    for d in data:
        if isinstance(d, str):
            contents.append(to_bytes(d))
        elif isinstance(d, bytes):
            contents.append(d)
        else:
            raise TypeError('response content type error')

    if contents:
        response.content = contents
    if not response.content_type:
        # set default content-type
        response.content_type = 'text/plain'
    response.code = code
    return response


def url_redirect(code, location):
    raise HttpRedirect(code, location)


def url_for():
    pass


class TemplateEngine:

    def __init__(self):
        pass

    env = Environment(
        loader=PackageLoader('__main__', 'templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )


class WispyException(Exception):
    pass


class RouteBuildException(WispyException):
    pass


class Wispy:

    def __init__(self, static_name='static', static_path=None, template_path=None):
        self.root_path = os_path.abspath(os_path.dirname(__file__))

        if not static_path:
            self.static_path = os_path.join(self.root_path, 'static')

        if not template_path:
            self.template_path = os_path.join(self.root_path, 'templates')

        self.static_name = static_name

        self.before_interceptors = []
        self.after_interceptors = []

        self.router = Router()

        self.template_engine = Environment(
            loader=PackageLoader('__main__', 'templates'),
            autoescape=select_autoescape(['html', 'xml']))

    def get(self, url_path):
        def decorated(callback):
            self.router.add_view_route(url_path, 'GET', callback)
            return callback

        return decorated

    def post(self, url_path):
        def decorated(callback):
            self.router.add_view_route(url_path, 'POST', callback)
            return callback

        return decorated

    def options(self, url_path):
        def decorated(callback):
            self.router.add_view_route(url_path, 'OPTIONS', callback)
            return callback

        return decorated

    def head(self, url_path):
        def decorated(callback):
            self.router.add_view_route(url_path, 'HEAD', callback)
            return callback

        return decorated

    def view(self, template_name):
        def wrapper(callback):
            @functools.wraps(callback)
            def decorated(*args, **kwargs):
                ctx.response.content_type = 'text/html'
                template = self.template_engine.get_template(template_name)
                return template.render(**callback(*args, **kwargs))

            return decorated

        return wrapper

    def before_request(self, callback):
        self.before_interceptors.append(callback)
        return callback

    def after_request(self, callback):
        self.after_interceptors.append(callback)
        return callback

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
        except HttpRedirect as e:
            start_response(e.status, e.headers)
            return []
        except HttpError as e:
            start_response(e.status, e.headers)
            return [to_bytes(e.status)]
        except Exception as e:
            if getattr(self, 'debug', False) is True:
                traceback.print_exc()
            else:
                logging.exception(e)
            status = get_response_status(500)
            start_response(status, [])
            return [to_bytes(status)]
        finally:
            del ctx.request
            del ctx.response
            del ctx.current_app


if __name__ == '__main__':
    app = Wispy()


    @app.get('/')
    def index():
        print(ctx.request.headers.user_agent)
        ctx.response.set_cookie('index', 'hello')
        ctx.response.set_cookie('index1', 'hello1')
        return 'hello'


    @app.get('/index/<name>/<username>')
    @app.view('index.html')
    def test(name, username):
        return dict(username=username)


    @app.get('/home')
    def home():
        return url_redirect(302, 'http://www.baidu.com')


    @app.get('/user/<int:id>')
    def user(id):
        return str(type(id))


    @app.get('/user1/<float:id>')
    def test_fload(id):
        return str(type(id))


    doctest.testmod()

    app.run(host='localhost', port=8080, debug=True)
