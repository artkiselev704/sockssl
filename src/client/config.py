import logging
import os

assert 'PASSWORD' in os.environ
assert 'SERVER_HOST' in os.environ


def log_level() -> int:
    """
    Logging level
    """
    return int(os.environ.get('LOG_LEVEL', logging.INFO))


def timeout() -> int:
    """
    Connection timeout
    """
    return int(os.environ.get('TIMEOUT', 10))


def buffer_size() -> int:
    """
    Socket buffer size
    """
    return int(os.environ.get('BUFFER_SIZE', 1024))


def password() -> str:
    """
    Proxy password
    """
    return os.environ['PASSWORD']


def client_host() -> str:
    """
    Client host for binding
    """
    return os.environ.get('CLIENT_HOST', '0.0.0.0')


def client_port() -> int:
    """
    Client port for binding
    """
    return int(os.environ.get('CLIENT_PORT', 1080))


def server_host() -> str:
    """
    Proxy server host
    """
    return os.environ['SERVER_HOST']


def server_port() -> int:
    """
    Proxy server port
    """
    return int(os.environ.get('SERVER_PORT', 443))
