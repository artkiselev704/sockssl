import logging
import socket
import ssl

from _shared import base
from _shared.protocol import socks, injector
from client import config

logging.basicConfig(level=config.log_level())


class SocksSSLClient(base.SocksSSLBase):
    pass


class SocksSSLClientHandler(base.SocksSSLBaseHandler):
    def _handle_session(self) -> None:
        self.request.settimeout(config.timeout())
        self._handle_socks_handshake()

    def _handle_socks_handshake(self) -> None:
        self._debug('_handle_socks_handshake')

        sock = self.request
        data = socks.get_handshake(sock.recv(config.buffer_size()))

        if data['ver'] != socks.VERSION:
            raise base.SocksSSLException(
                'SOCKS handshake error - unsupported version. ({})'.format(data['ver']))

        if socks.METHOD.NO_AUTH not in data['methods']:
            raise base.SocksSSLException(
                'SOCKS handshake error - unsupported methods. ({})'.format(data['methods']))

        sock.sendall(socks.reply_handshake(socks.METHOD.NO_AUTH))
        self._handle_socks_request()

    def _handle_socks_request(self) -> None:
        self._debug('_handle_socks_request')

        sock = self.request
        data = socks.get_request(sock.recv(config.buffer_size()))

        if data['ver'] != socks.VERSION:
            raise base.SocksSSLException(
                'SOCKS request error - unsupported version ({})'.format(data['ver']))

        if data['cmd'] != socks.CMD.CONNECT:
            sock.sendall(
                socks.reply_request(socks.REPLY.CMD_NOT_SUPPORTED, data['atyp'], data['dst_addr'], data['dst_port']))
            raise base.SocksSSLException(
                'SOCKS request error - unsupported command. ({})'.format(data['cmd']))

        if data['atyp'] not in [socks.ATYP.IPV4, socks.ATYP.DOMAINNAME]:
            sock.sendall(
                socks.reply_request(socks.REPLY.ATYP_NOT_SUPPORTED, data['atyp'], data['dst_addr'], data['dst_port']))
            raise base.SocksSSLException(
                'SOCKS request error - unsupported address type. ({})'.format(data['atyp']))

        try:
            dst = base.connect(config.server_host(), config.server_port(), config.timeout())

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            dst = ctx.wrap_socket(dst)
        except socket.error as err:
            sock.sendall(
                socks.reply_request(socks.REPLY.CONNECTION_REFUSED, data['atyp'], data['dst_addr'], data['dst_port']))
            raise base.SocksSSLException(
                'SOCKS request error - server connection failed. ({})'.format(err))

        sock.sendall(
            socks.reply_request(socks.REPLY.SUCCEEDED, data['atyp'], data['dst_addr'], data['dst_port']))
        self._handle_injector_handshake(dst, data['dst_addr'], data['dst_port'])

    def _handle_injector_handshake(self, dst: socket.socket, dst_addr: str, dst_port: int) -> None:
        self._debug('_handle_injector_handshake')

        # Handshake request
        dst.sendall(injector.do_handshake(config.password(), dst_addr, dst_port))

        # Handshake validation
        data = injector.get_handshake(dst.recv(config.buffer_size()))

        if data['version'] != injector.VERSION:
            raise base.SocksSSLException(
                'Injector validation error - version mismatch. ({})'.format(data['version']))

        if data['password'] != config.password():
            raise base.SocksSSLException(
                'Injector validation error - password mismatch. ({})'.format(data['password']))

        if data['dst_addr'] != dst_addr:
            raise base.SocksSSLException(
                'Injector validation error - destination address mismatch. ({})'.format(data['dst_addr']))

        if data['dst_port'] != dst_port:
            raise base.SocksSSLException(
                'Injector validation error - destination port mismatch. ({})'.format(data['dst_port']))

        self._handle_exchange(dst)

    def _handle_exchange(self, dst: socket.socket) -> None:
        self._debug('_handle_exchange')
        base.exchange(self.request, dst, config.buffer_size())


def main() -> None:
    base.run(SocksSSLClient, SocksSSLClientHandler, (config.client_host(), config.client_port()))


if __name__ == '__main__':
    main()
