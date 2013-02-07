#!/usr/bin/python
# coding: utf-8
from itertools import chain
import logging

import sys
from StringIO import StringIO
from wsgi import IcapWsgiHandler

log = logging.getLogger('icap')


class BadIcapRequest(ValueError):
    def __init__(self, code=400, *args):
        self.code = code
        ValueError.__init__(self, code, *args)


class ChunkedError(ValueError):
    pass


class NoBlockpageNeeded(Exception):
    pass


class BadHttpRequest(Exception):
    pass


MAX_ICAP_HEADER_LEN = 8190
MAX_HTTP_HEADER_LEN = 8190
MAX_CHUNKLEN_LEN = 20
MAX_HTTP_TRAILER_LEN = 8190

icap_errors = {
    400: "Bad Request",
    413: "Request Entity Too Large",
    418: "Bad Composition",
    500: "Server Error",
    501: "Method Not Implemented",
    505: "ICAP Version Not Supported",
}

http_errors = {
    400: ["Bad Request",
          "Your browser sent a request that this "
          "server could not understand."
    ],
    505: ["HTTP Version Not Supported",
          "Your browser sent a request "
          "using a version of HTTP protocol that this server does not "
          "support."
    ],
}


class ICAP(object):
    def __init__(self):
        """
        Создает ICAP-сессию.

        application - это псевдо-WSGI-приложение, используемое как страница
        блокировки. Отличие от настоящего WSGI: HTTP-код 204 рассматривается
        как признак, что запрос не надо блокировать, и тело POST-запросов не
        передается (все не-GET-запросы преобразуются в GET).

        remote_addr - предполагается, что туда будет передан IP-адрес прокси,
        который послал ICAP-запрос.

        В качестве переменных окружения, WSGI-приложению передаются:
        REMOTE_ADDR: адрес прокси-сервера
        HTTP_X_CLIENT_IP: адрес клиента этого прокси (если известен)
        """

        self._buffered_line = []
        self._init_request()
        self._expect_icap_firstline()

    def parse(self, data):
        """
        Обрабатывает порцию входящих данных протокола ICAP.

        data - строка с порцией входящих данных

        Возвращает tuple(reply, close_now), где reply - (возможно пустая)
        строка, которую надо послать обратно клиенту, close_now - булев
        флаг, который означает, что после отправки reply надо закрыть
        соединение.

        :type data: bytes

        """

        dpos = 0
        portions = []
        close_now = False
        while dpos != len(data) and not close_now:
            try:
                dpos, portion, close_now = self._mode(data, dpos)
                if portion:
                    portions.append(portion)
                    self._reply_started = True
            except ChunkedError:
                close_now = True
            except BadIcapRequest as e:
                portions.append(self._make_icap_error(e.code))
                close_now = True
            except Exception:
                if not self._reply_started:
                    portions.append(self._make_icap_error(500))
                close_now = True
        return ''.join(portions), close_now

    # Все ниже этой строки - детали реализации.
    def _init_request(self):
        self._deferred_error_code = None
        self._icap_method = None
        self._icap_uri = None
        self._icap_version = None
        self._icap_host = None
        self._allow_204 = False
        self._connection_close = False
        self._has_preview = False
        self._http_hdr_len = None
        self._http_host = None
        self._http_headers = []
        self._reply_started = False
        self._has_body = False
        self._client_ip = None

    def _flatten_headers(self, headers):
        """
        :type headers: list
        """
        if self._connection_close:
            return '\r\n'.join(chain(headers, ['Connection: close', '', ''])), True
        else:
            # TODO: Force Connection: keep-alive ?!
            return '\r\n'.join(chain(headers, ['',  ''])), False

    def _register_line_portion(self, portion):
        """
        :type portion: bytes
        """
        self._buffered_line.append(portion)
        self._max_len -= len(portion)

    def _linemode(self, data, offset):
        """
        :type offset: int
        :type data: bytes
        """
        xpos = data.find('\n', offset, offset + self._max_len)
        if xpos != -1:
            self._register_line_portion(data[offset:xpos + 1])
            ret = self._on_data(''.join(self._buffered_line))
            self._buffered_line = []
            return (xpos + 1,) + ret

        if offset + self._max_len <= len(data):
            raise self._length_exception

        self._register_line_portion(data[offset:])
        return len(data), "", False

    def _bytemode(self, data, offset):
        """
        :type offset: int
        :type data: bytes
        """
        if offset + self._max_len <= len(data):
            endpos = offset + self._max_len
            self._max_len = 0
            ret = self._on_data(data[offset:endpos])
            return (endpos,) + ret

        self._max_len -= len(data) - offset
        ret = self._on_data(data[offset:])
        return (len(data),) + ret


    def _expect_icap_firstline(self):
        self._mode = self._linemode
        self._on_data = self._parse_icap_firstline
        self._max_len = MAX_ICAP_HEADER_LEN
        self._length_exception = BadIcapRequest(413)

    def _parse_icap_firstline(self, line):
        """
        :type line: bytes
        """
        self._init_request()
        try:
            self._icap_method, self._icap_uri, self._icap_version = line.split(' ')
        except ValueError:
            raise BadIcapRequest(400)

        if not self._icap_version.startswith('ICAP/1.'):
            raise BadIcapRequest(505)

        # XXX validate the URI
        self._expect_icap_header()
        return '', False

    def _expect_icap_header(self):
        # self._mode = self._linemode                   # i.e. unchanged
        self._on_data = self._parse_icap_header
        # self._max_len is unchanged
        # self._length_exception = BadIcapRequest(413)  # i.e. unchanged

    def _parse_icap_header(self, line):
        """
        :type line: bytes
        """
        if line == '\r\n' or line == '\n':
            return self._parse_icap_emptyline()

        try:
            key, value = line.split(':', 1)
        except ValueError:
            raise BadIcapRequest(400)

        key, value = key.lower(), value.strip()

        if key == 'host':
            if self._icap_host is not None:
                self._deferred_error_code = 400
            self._icap_host = value

        elif key == 'allow':
            if '204' in (x.strip() for x in value.split(',')):
                self._allow_204 = True

        elif key == 'x-client-ip':
            if self._client_ip is not None:
                self._deferred_error_code = 400
            self._client_ip = value  # XXX: validate as IP

        elif key == 'connection':
            if 'close' in (x.strip() for x in value.split(',')):
                self._connection_close = True

        elif key == 'encapsulated':
            # XXX: do something about duplicate headers
            value = value.replace(' ', '')
            if value.startswith('req-hdr=0,req-body='):
                self._http_hdr_len = int(value[19:], 10)
                self._has_body = True
            elif value.startswith('req-hdr=0,null-body='):
                self._http_hdr_len = int(value[20:], 10)
                self._has_body = False
            elif value == 'null-body=0':
                self._http_hdr_len = None
                self._has_body = False
            else:
                self._deferred_error_code = 418

        elif key == 'preview':
            self._has_preview = True

        # All other headers are silently ignored
        return '', False

    def _parse_icap_emptyline(self):
        if self._deferred_error_code is not None:
            raise BadIcapRequest(self._deferred_error_code)
        if self._icap_host is None:
            raise BadIcapRequest(400)

        # XXX more validation of host
        if self._icap_method == 'OPTIONS':
            if self._http_hdr_len is not None:
                raise BadIcapRequest(418)
            self._expect_icap_firstline()
            return self._flatten_headers([
                'ICAP/1.0 200 OK',
                'Methods: REQMOD',
                'Service: SkyDNS ICAP',
                'Encapsulated: null-body=0',
                'Max-Connections: 15',
                'Options-TTL: 3600',
                'Allow: 204',
                'Preview: 0',
            ])

        if self._icap_method != 'REQMOD':
            raise BadIcapRequest(501)

        if self._http_hdr_len is None:
            raise BadIcapRequest(418)

        try:
            self._max_len = int(self._http_hdr_len)
        except ValueError:
            raise BadIcapRequest(400)

        if self._max_len < 0:
            raise BadIcapRequest(400)
        if self._max_len > MAX_HTTP_HEADER_LEN:
            raise BadIcapRequest(413)

        if self._has_preview and not self._has_body:
            raise BadIcapRequest(400)

        self._expect_http_firstline()

        return '', False

    def _expect_http_firstline(self):
        # self._mode = self._linemode    # i.e. unchanged
        # self._max_len is already set in parse_icap_emptyline
        self._length_exception = BadIcapRequest(400)
        self._on_data = self._parse_http_firstline

    def _parse_http_firstline(self, line):
        """
        :type line: bytes
        """
        try:
            self._http_method, self._http_uri, self._http_version = line.split(' ')
        except ValueError:
            self._deferred_error_code = 400
            self._expect_http_header_garbage()
            return '', False
        if not self._http_version.startswith('HTTP/1.'):
            self._deferred_error_code = 505
            self._expect_http_header_garbage()
            return '', False
        self._http_headers = [line]
        self._expect_http_header()
        return '', False

    def _expect_http_header_garbage(self):
        self._mode = self._bytemode
        # self._max_len is unchanged
        # self._length_exception does not make sense in byte mode
        self._on_data = self._parse_http_header_garbage

    #noinspection PyUnusedLocal
    def _parse_http_header_garbage(self, data):
        if self._max_len == 0:
            return self._parse_http_emptyline()
        return '', False

    def _expect_http_header(self):
        # self._mode = self._linemode                    # i.e. unchanged
        # self._max_len is unchanged
        # self._length_exception = BadIcapRequest(400)  # i.e. unchanged
        self._on_data = self._parse_http_header

    def _parse_http_header(self, line):
        """
        :type line: bytes
        """
        self._http_headers.append(line)
        if line == '\r\n' or line == '\n':
            return self._parse_http_emptyline()

        try:
            key, value = line.split(':', 1)
        except ValueError:
            raise BadHttpRequest(400)

        key, value = key.lower(), value.strip()

        if key == 'host':
            if self._http_host is not None:
                self._deferred_error_code = 400
            self._http_host = value

        return '', False

    def _parse_http_emptyline(self):
        if self._max_len != 0:
            raise BadIcapRequest(400)

        # XXX validate http_url vs http_host
        #if self._http_host is None:
        #    raise BadHttpRequest(400)

        if self._has_body:
            self._expect_chunklen_line()
            close_now = False
        else:
            self._expect_icap_firstline()
            close_now = self._connection_close

        if self._deferred_error_code is not None:
            self._eat_body = True
            return self._make_http_error(self._deferred_error_code), close_now

        try:
            bp = self._make_blockpage()
            self._eat_body = True
            return bp, close_now
        except NoBlockpageNeeded:
            pass

        if self._has_preview or self._allow_204:
            self._eat_body = True
            return self._flatten_headers([
                'ICAP/1.0 204 No Modifications Needed',
                'Service: SkyDNS ICAP',
                'Encapsulated: null-body=0',
            ])[0], close_now

        self._eat_body = False
        return self._make_200_mirror_response(), close_now

    def _maybe_eat(self, data):
        """
        :type data: bytes
        """
        return '' if self._eat_body else data

    def _expect_chunklen_line(self):
        self._mode = self._linemode
        self._on_data = self._parse_chunklen_line
        self._max_len = MAX_CHUNKLEN_LEN
        self._length_exception = ChunkedError()

    def _parse_chunklen_line(self, line):
        """
        :type line: bytes
        """
        semicolon = line.find(';') # -1 is OK, too
        try:
            self._max_len = int(line[:semicolon], 16)
        except:
            raise ChunkedError
        if self._max_len < 0:
            raise ChunkedError

        if self._max_len == 0:
            self._expect_trailer_line()
        else:
            self._expect_chunk()
        return self._maybe_eat(line), False

    def _expect_chunk(self):
        self._mode = self._bytemode
        self._on_data = self._parse_chunk
        # self._max_len is set by parse_chunklen_line()
        # self._length_exception does not make sense in byte mode

    def _parse_chunk(self, chunk):
        """
        :type chunk: bytes
        """
        if self._max_len == 0:
            self._expect_crlf_after_chunk()
        return self._maybe_eat(chunk), False

    def _expect_crlf_after_chunk(self):
        self._mode = self._linemode
        self._on_data = self._parse_crlf_after_chunk
        self._max_len = 2
        # self._length_exception = ChunkedError()  # i.e. unchanged

    def _parse_crlf_after_chunk(self, line):
        """
        :type line: bytes
        """
        if line == '\r\n' or line == '\n':
            self._on_data = self._parse_chunklen_line
            self._max_len = MAX_CHUNKLEN_LEN
            return self._maybe_eat(line), False
        raise ChunkedError

    def _expect_trailer_line(self):
        # self._mode = self._linemode               # i.e. unchanged
        self._on_data = self._parse_trailer_line
        self._max_len = MAX_HTTP_TRAILER_LEN
        # self._length_exception = ChunkedError()  # i.e. unchanged

    def _parse_trailer_line(self, line):
        """
        :type line: bytes
        """
        close_now = False
        if line == '\r\n' or line == '\n':
            close_now = self._connection_close
            self._expect_icap_firstline()
        return self._maybe_eat(line), close_now

    def _make_http_response_ex(self, http_headers, http_body):
        """
        :type http_body: bytes
        :type http_headers: bytes
        """
        icap_headers = [
            "ICAP/1.0 200 OK",
            "Service: SkyDNS ICAP",
            "Encapsulated: res-hdr=0, res-body={0}".format(len(http_headers))
        ]

        # chunkize http_body :)
        # TODO: of body is generator - generate chunks using yield
        if http_body:
            http_body = '{0:x}\r\n{1}\r\n'.format(len(http_body), http_body)

        return self._flatten_headers(icap_headers)[0] + http_headers + http_body + '0\r\n\r\n'

    def _make_blockpage(self):
        stdin = StringIO('')
        hdrout = StringIO()
        bodyout = StringIO()
        stderr = sys.stderr
        env = {
            'REMOTE_ADDR': self._remote_addr,
            'SERVER_PROTOCOL': self._http_version,
            'REQUEST_METHOD': 'GET', # fake
            'HTTP_HOST': self._http_host or "_default_",
            'HTTP_X_CLIENT_IP': self._client_ip,
            # TODO: other variables, but not everything!
        }

        handler = IcapWsgiHandler(stdin, hdrout, bodyout, stderr, env)
        handler.run(self._application)

        stdin.close()
        http_headers = hdrout.getvalue()
        hdrout.close()
        http_body = bodyout.getvalue()
        bodyout.close()

        if http_headers.startswith("HTTP/1.1 204 ") or http_headers.startswith("HTTP/1.0 204 "):
            raise NoBlockpageNeeded

        return self._make_http_response_ex(http_headers, http_body)

    def _make_200_mirror_response(self):
        ret = [
            'ICAP/1.0 200 OK',
            'Server: SkyDNS ICAP',
            'Encapsulated: req-hdr=0, {0}-body={1}'.format('req' if self._has_body else 'null', self._http_hdr_len),
        ]
        if self._connection_close:
            ret.append('Connection: close')
        ret.append('')
        ret.append('')
        return '\r\n'.join(ret) + ''.join(self._http_headers)

    def _make_icap_error(self, code):
        """
        :type code: int
        """
        errorstr = icap_errors.get(code, None)
        if errorstr is None:
            log.error('Unknown Icap error code', code)
            errorstr = 'Unknown error'

        return '\r\n'.join([
            'ICAP/1.0 {0} {1}'.format(code, errorstr),
            "Server: SkyDNS ICAP",
            "Encapsulated: null-body=0",
            "Connection: close",
            '',
            '',
        ])

    def _make_http_error(self, code):
        """
        :type code: int
        """
        error_info = http_errors.get(code, None)
        if error_info is None:
            log.error('Unknown http error', code)
            short_text = "Unknown Error"
            long_text = ("Your browser sent a well-formed request "
                         "that was nevertheless classified as an error. No further "
                         "information is available at this time.")
        else:
            (short_text, long_text) = error_info

        html = ("<html><head><title>{0}</title></head>"
                "<body><h1>{1}</h1><p>{2}</p></body></html>".format(short_text, short_text, long_text))

        http_headers = '\r\n'.join([
            "HTTP/1.1 {0} {1}".format(code, short_text),
            "Content-Type: text/html",
            "Content-Length: {0}".format(len(html)),
            '',
        ])

        return self._make_http_response_ex(http_headers, html)
