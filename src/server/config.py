import logging
import os

assert 'PASSWORD' in os.environ
assert 'TARGET_HOST' in os.environ


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


def server_host() -> str:
    """
    Proxy server host for binding
    """
    return os.environ.get('SERVER_HOST', '0.0.0.0')


def server_port() -> int:
    """
    Proxy server port for binding
    """
    return int(os.environ.get('SERVER_PORT', 443))


def target_host() -> str:
    """
    Target server host
    """
    return os.environ['TARGET_HOST']


def target_port() -> int:
    """
    Target server port
    """
    return int(os.environ.get('TARGET_PORT', 80))
