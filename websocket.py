"""
Websocket client for protocol version 13 using the Tornado IO loop.

http://tools.ietf.org/html/rfc6455

Based on the websocket server in tornado/websocket.py by Jacob Kristhammar.
"""
import array
import base64
import functools
import hashlib
import logging
import os
import re
import socket
import struct
import sys
import time
import urllib.parse

import tornado.escape
from tornado import ioloop, iostream
from tornado.httputil import HTTPHeaders
from tornado.util import bytes_type

if type('') is not type(b''):
    def b(s):
        return s.encode('latin1')
else:
    def b(s):
        return s


# The initial handshake over HTTP.
INIT = """\
GET %(path)s HTTP/1.1
Host: %(host)s:%(port)s
Upgrade: websocket
Connection: Upgrade
Sec-Websocket-Key: %(key)s
Sec-Websocket-Version: 13\
"""

# Magic string defined in the spec for calculating keys.
MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def frame(data, opcode=0x01):
    """Encode data in a websocket frame."""
    # [fin, rsv, rsv, rsv] [opcode]
    frame = struct.pack('B', 0x80 | opcode)

    # Our next bit is 1 since we're using a mask.
    length = len(data)
    if length < 126:
        # If length < 126, it fits in the next 7 bits.
        frame += struct.pack('B', 0x80 | length)
    elif length <= 0xFFFF:
        # If length < 0xffff, put 126 in the next 7 bits and write the length
        # in the next 2 bytes.
        frame += struct.pack('!BH', 0x80 | 126, length)
    else:
        # Otherwise put 127 in the next 7 bits and write the length in the next
        # 8 bytes.
        frame += struct.pack('!BQ', 0x80 | 127, length)

    # Clients must apply a 32-bit mask to all data sent.
    mask = list(map(int, os.urandom(4)))
    frame += struct.pack('!BBBB', *mask)
    # Mask each byte of data using a byte from the mask.
    msg = [int(c) ^ mask[i % 4] for i, c in enumerate(data)]
    frame += struct.pack('!' + 'B' * length, *msg)
    return frame


class WebSocket(object):
    """Websocket client for protocol version 13 using the Tornado IO loop."""

    def __init__(self, url, io_loop=None, extra_headers=None):
        ports = {'ws': 80, 'wss': 443}

        self.io_loop = io_loop
        if not self.io_loop:
            self.io_loop = ioloop.IOLoop.instance()

        self.url = urllib.parse.urlparse(url)
        self.host = self.url.hostname
        self.port = self.url.port or ports[self.url.scheme]
        self.path = self.url.path or '/'

        if extra_headers is not None and len(extra_headers) > 0:
            header_set = []
            for k, v in extra_headers.items():
                header_set.append("%s: %s" % (k, v))
            self.headers = "\r\n".join(header_set)
        else:
            self.headers = None

        self.client_terminated = False
        self.server_terminated = False
        self._final_frame = False
        self._frame_opcode = None
        self._frame_length = None
        self._fragmented_message_buffer = None
        self._fragmented_message_opcode = None
        self._waiting = None

        self.key = base64.b64encode(os.urandom(16)).decode('utf-8')
        self.stream = iostream.IOStream(socket.socket())

    async def start(self):
        await self.stream.connect((self.host, self.port))
        await self._on_connect()

    async def on_open(self):
        pass

    async def on_message(self, data):
        pass

    async def on_ping(self):
        pass

    async def on_pong(self):
        pass

    async def on_close(self):
        pass

    async def on_unsupported(self):
        pass

    async def write_message(self, message, binary=False):
        """Sends the given message to the client of this Web Socket."""
        if binary:
            opcode = 0x2
        else:
            opcode = 0x1
        message = tornado.escape.utf8(message)
        assert isinstance(message, bytes_type)
        await self._write_frame(True, opcode, message)

    async def ping(self):
        await self._write_frame(True, 0x9, b(''))

    async def close(self):
        """Closes the WebSocket connection."""
        if not self.server_terminated:
            if not self.stream.closed():
                await self._write_frame(True, 0x8, b(""))
            self.server_terminated = True
        if self.client_terminated:
            if self._waiting is not None:
                self.stream.io_loop.remove_timeout(self._waiting)
                self._waiting = None
            self.stream.close()
        elif self._waiting is None:
            # Give the client a few seconds to complete a clean shutdown,
            # otherwise just close the connection.
            self._waiting = self.stream.io_loop.add_timeout(
                time.time() + 5, self._abort)

    async def _write_frame(self, fin, opcode, data):
        await self.stream.write(frame(data, opcode))

    async def _on_connect(self):
        request = '\r\n'.join(INIT.splitlines()) % self.__dict__
        if self.headers is not None:
            request += '\r\n' + self.headers
        request += '\r\n\r\n'
        await self.stream.write(tornado.escape.utf8(request))
        data = await self.stream.read_until(b'\r\n\r\n')
        await self._on_headers(data)

    async def _on_headers(self, data):
        first, _, rest = data.partition(b'\r\n')
        first = first.decode('utf-8')
        rest = rest.decode('utf-8')
        headers = HTTPHeaders.parse(rest)
        # Expect HTTP 101 response.
        if not re.match('HTTP/[^ ]+ 101', first):
            await self._async_callback(self.on_unsupported)()
            await self.close()
        else:
            # Expect Connection: Upgrade.
            assert headers['Connection'].lower() == 'upgrade'
            # Expect Upgrade: websocket.
            assert headers['Upgrade'].lower() == 'websocket'
            # Sec-WebSocket-Accept should be derived from our key.
            accept = base64.b64encode(hashlib.sha1((self.key + MAGIC).encode('utf-8')).digest()).decode('utf-8')
            assert headers['Sec-WebSocket-Accept'] == accept

            await self._async_callback(self.on_open)()
            await self._receive_frame()

    async def _receive_frame(self):
        data = await self.stream.read_bytes(2)
        await self._on_frame_start(data)

    async def _on_frame_start(self, data):
        header, payloadlen = struct.unpack("BB", data)
        self._final_frame = header & 0x80
        reserved_bits = header & 0x70
        self._frame_opcode = header & 0xf
        self._frame_opcode_is_control = self._frame_opcode & 0x8
        if reserved_bits:
            # client is using as-yet-undefined extensions; abort
            await self._abort()
        if (payloadlen & 0x80):
            # Masked frame -> abort connection
            await self._abort()
        payloadlen = payloadlen & 0x7f
        if self._frame_opcode_is_control and payloadlen >= 126:
            # control frames must have payload < 126
            await self._abort()
        if payloadlen < 126:
            self._frame_length = payloadlen
            _data = await self.stream.read_bytes(self._frame_length)
            await self._on_frame_data(_data)
        elif payloadlen == 126:
            _data = await self.stream.read_bytes(2)
            await self._on_frame_length_16(_data)
        elif payloadlen == 127:
            _data = await self.stream.read_bytes(8)
            await self._on_frame_length_64(_data)

    async def _on_frame_length_16(self, data):
        self._frame_length = struct.unpack("!H", data)[0]
        _data = await self.stream.read_bytes(self._frame_length)
        await self._on_frame_data(_data)

    async def _on_frame_length_64(self, data):
        self._frame_length = struct.unpack("!Q", data)[0]
        _data = await self.stream.read_bytes(self._frame_length)
        await self._on_frame_data(_data)

    async def _on_frame_data(self, data):
        unmasked = array.array("B", data)

        if self._frame_opcode_is_control:
            # control frames may be interleaved with a series of fragmented
            # data frames, so control frames must not interact with
            # self._fragmented_*
            if not self._final_frame:
                # control frames must not be fragmented
                await self._abort()
                return
            opcode = self._frame_opcode
        elif self._frame_opcode == 0:  # continuation frame
            if self._fragmented_message_buffer is None:
                # nothing to continue
                await self._abort()
                return
            self._fragmented_message_buffer += unmasked
            if self._final_frame:
                opcode = self._fragmented_message_opcode
                unmasked = self._fragmented_message_buffer
                self._fragmented_message_buffer = None
        else:  # start of new data message
            if self._fragmented_message_buffer is not None:
                # can't start new message until the old one is finished
                await self._abort()
                return
            if self._final_frame:
                opcode = self._frame_opcode
            else:
                self._fragmented_message_opcode = self._frame_opcode
                self._fragmented_message_buffer = unmasked

        if self._final_frame:
            await self._handle_message(opcode, unmasked.tobytes())

        if not self.client_terminated:
            await self._receive_frame()

    async def _abort(self):
        """Instantly aborts the WebSocket connection by closing the socket"""
        self.client_terminated = True
        self.server_terminated = True
        self.stream.close()
        await self.close()

    async def _handle_message(self, opcode, data):
        if self.client_terminated:
            return

        if opcode == 0x1:
            # UTF-8 data
            try:
                decoded = data.decode("utf-8")
            except UnicodeDecodeError:
                await self._abort()
                return
            await self._async_callback(self.on_message)(decoded)
        elif opcode == 0x2:
            # Binary data
            await self._async_callback(self.on_message)(data)
        elif opcode == 0x8:
            # Close
            self.client_terminated = True
            await self.close()
        elif opcode == 0x9:
            # Ping
            await self._write_frame(True, 0xA, data)
            await self._async_callback(self.on_ping)()
        elif opcode == 0xA:
            # Pong
            await self._async_callback(self.on_pong)()
        else:
            await self._abort()

    def _async_callback(self, callback, *args, **kwargs):
        """Wrap callbacks with this if they are used on asynchronous requests.

        Catches exceptions properly and closes this WebSocket if an exception
        is uncaught.
        """
        if args or kwargs:
            callback = functools.partial(callback, *args, **kwargs)

        async def wrapper(*args, **kwargs):
            try:
                await callback(*args, **kwargs)
            except Exception:
                logging.error('Uncaught exception', exc_info=True)
                await self._abort()

        return wrapper


def main(url, message='hello, world'):
    class HelloSocket(WebSocket):

        async def on_open(self):
            await self.ping()
            print('>> ' + message)
            await self.write_message(message)

        async def on_message(self, data):
            print('on_message: ' + data)
            msg = eval(input('>> '))
            if msg == 'ping':
                await self.ping()
            elif msg == 'die':
                await self.close()
            else:
                await self.write_message(msg)

        async def on_close(self):
            print('on_close')

        async def on_pong(self):
            print('on_pong')

    ws = HelloSocket(url)
    try:
        ioloop.IOLoop.current().run_sync(ws.start)
    except KeyboardInterrupt:
        pass
    finally:
        ioloop.IOLoop.current().run_sync(ws.close)

if __name__ == '__main__':
    main(*sys.argv[1:])
