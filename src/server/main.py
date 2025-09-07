import logging
import socket
import ssl

from _shared import base
from _shared.protocol import injector
from server import config

logging.basicConfig(level=config.log_level())


class SocksSSLServer(base.SocksSSLBase):
    _context: ssl.SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    def __init__(self, server_address, request_handler_class, bind_and_activate=True):
        self._context.load_cert_chain('./_data/cert.pem', './_data/key.pem')
        super().__init__(server_address, request_handler_class, bind_and_activate)

    def get_request(self):
        new_socket, from_addr = self.socket.accept()
        stream = self._context.wrap_socket(new_socket, server_side=True)
        return stream, from_addr


class SocksSSLServerHandler(base.SocksSSLBaseHandler):
    def _handle_session(self) -> None:
        self.request.settimeout(config.timeout())
        self._handle_injector_handshake()

    def _handle_injector_handshake(self) -> None:
        self._debug('_handle_injector_handshake')

        sock = self.request
        data = sock.recv(config.buffer_size())

        try:
            hs = injector.get_handshake(data)

            if hs['version'] != injector.VERSION:
                raise base.SocksSSLException(
                    'Injector handshake error - unsupported version. ({})'.format(hs['version']))

            if hs['password'] != config.password():
                raise base.SocksSSLException(
                    'Injector handshake error - invalid password. ({})'.format(hs['password']))

            dst = base.connect(hs['dst_addr'], hs['dst_port'], config.timeout())
            sock.sendall(injector.do_handshake(hs['password'], hs['dst_addr'], hs['dst_port']))

        except Exception as e:
            self._debug('Injector handshake error: {}'.format(e))
            dst = base.connect(config.target_host(), config.target_port(), config.timeout())
            dst.sendall(data)

        self._handle_exchange(dst)

    def _handle_exchange(self, dst: socket.socket) -> None:
        self._debug('_handle_exchange')
        base.exchange(self.request, dst, config.buffer_size())


def main() -> None:
    base.run(SocksSSLServer, SocksSSLServerHandler, (config.server_host(), config.server_port()))


if __name__ == '__main__':
    main()
