import logging
import socket
import socketserver

import select

_total_sessions: int = 0


class SocksSSLBase(socketserver.ThreadingMixIn, socketserver.TCPServer):
    _logger: logging.Logger

    def __init__(self, server_address, request_handler_class, bind_and_activate=True):
        self._logger = logging.getLogger(type(self).__name__)
        super().__init__(server_address, request_handler_class, bind_and_activate)

    """
    Custom
    """

    def start(self) -> None:
        self._info('Service available at {}:{}'.format(self.server_address[0], self.server_address[1]))
        self.serve_forever()

    def stop(self) -> None:
        self._info('Waiting for sessions termination...')
        self.shutdown()

    """
    Logging
    """

    def _debug(self, message: str) -> None:
        self._logger.debug(message)

    def _info(self, message: str) -> None:
        self._logger.info(message)

    def _warning(self, message: str) -> None:
        self._logger.warning(message)


class SocksSSLBaseHandler(socketserver.BaseRequestHandler):
    _logger: logging.Logger

    def __init__(self, request, client_address, server):
        self._logger = logging.getLogger(type(self).__name__)
        super().__init__(request, client_address, server)

    def handle(self) -> None:
        global _total_sessions

        _total_sessions += 1
        self._info('Session started. Total sessions count: {}'.format(_total_sessions))

        try:
            self._handle_session()
        except Exception as e:
            self._warning('Terminated: {}'.format(e))

        _total_sessions -= 1
        self._info('Session ended. Total sessions count: {}'.format(_total_sessions))

    """
    Custom
    """

    def _handle_session(self) -> None:
        raise NotImplemented

    """
    Logging
    """

    def _debug(self, message: str) -> None:
        addr, port = self.request.getpeername()
        self._logger.debug('{}:{}:{}'.format(addr, port, message))

    def _info(self, message: str) -> None:
        addr, port = self.request.getpeername()
        self._logger.info('{}:{}:{}'.format(addr, port, message))

    def _warning(self, message: str) -> None:
        addr, port = self.request.getpeername()
        self._logger.warning('{}:{}:{}'.format(addr, port, message))


class SocksSSLException(RuntimeError):
    pass


def run(base_class: type[SocksSSLBase], handler_class: type[SocksSSLBaseHandler], server_addr: tuple[str, int]) -> None:
    with base_class(server_addr, handler_class) as server:
        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()


def exchange(src: socket.socket, dst: socket.socket, buffer_size: int = 1024) -> None:
    try:
        while True:
            sock_read, _, _ = select.select([src, dst], [], [])
            for sock in sock_read:
                data = sock.recv(buffer_size)
                if len(data) == 0:
                    raise ConnectionError
                if sock == src:
                    dst.sendall(data)
                    continue
                if sock == dst:
                    src.sendall(data)
                    continue
    except ConnectionError:
        pass


def connect(addr: str, port: int, timeout: int = 10) -> socket.socket:
    dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dst.connect((addr, port))
    dst.settimeout(timeout)
    return dst
