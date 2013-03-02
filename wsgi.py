# coding=utf-8
import wsgiref.handlers

#noinspection PyClassicStyleClass
class IcapWsgiHandler(wsgiref.handlers.BaseHandler):
    server_software = "my software"
    os_environ = {}
    http_version = "1.1"

    def __init__(self, stdin, hdrout, bodyout, stderr, environ):
        self.stdin = stdin
        self.hdrout = hdrout
        self.bodyout = bodyout
        self.stderr = stderr
        self.base_env = environ
        self.headers_written = False

    def _write(self, data):
        if self.headers_written:
            self.bodyout.write(data)
        else:
            self.hdrout.write(data)

    def _flush(self):
        if self.headers_written:
            self.bodyout.flush()
        else:
            self.hdrout.flush()

    def get_stdin(self):
        return self.stdin

    def get_stderr(self):
        return self.stderr

    def add_cgi_vars(self):
        self.environ.update(self.base_env)

    def send_headers(self):
        wsgiref.handlers.BaseHandler.send_headers(self)
        self.headers_written = True

    def close(self):
        wsgiref.handlers.BaseHandler.close(self)
        self.headers_written = False

