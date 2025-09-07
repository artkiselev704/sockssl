# RFC 1928 (https://datatracker.ietf.org/doc/html/rfc1928)

import socket

from bitstring import BitStream, pack

VERSION = 0x05
BUFFER_SIZE = 512


class METHOD:
    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERPASS = 0x02
    NO_ACCEPTABLE_METHODS = 0xff


class CMD:
    CONNECT = 0x01
    BIND = 0x02
    UDP = 0x04


class ATYP:
    IPV4 = 0x01
    DOMAINNAME = 0x03
    IPV6 = 0x04


class REPLY:
    SUCCEEDED = 0x00
    SERVER_FAILURE = 0x01
    NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    CMD_NOT_SUPPORTED = 0x07
    ATYP_NOT_SUPPORTED = 0x08


def get_handshake(data: bytes) -> dict:
    res = {}
    data = BitStream(data)

    res['ver'] = data.read('uint8')
    res['methods'] = [data.read('uint8') for _ in range(data.read('uint8'))]

    return res


def reply_handshake(method: int) -> bytes:
    data = BitStream()

    data += pack('uint8', VERSION)
    data += pack('uint8', method)

    return data.tobytes()


def get_request(data: bytes) -> dict:
    res = {}
    data = BitStream(data)

    res['ver'] = data.read('uint8')
    res['cmd'] = data.read('uint8')
    data.read('uint8')  # rsv
    res['atyp'] = data.read('uint8')

    if res['atyp'] == ATYP.IPV4:
        res['dst_addr'] = socket.inet_ntop(socket.AF_INET, data.read('bytes4'))
    elif res['atyp'] == ATYP.DOMAINNAME:
        length = data.read('uint8')
        res['dst_addr'] = data.read('bytes' + str(length)).decode()
    elif res['atyp'] == ATYP.IPV6:
        res['dst_addr'] = socket.inet_ntop(socket.AF_INET6, data.read('bytes16'))
    else:
        raise RuntimeError('Unknown ATYP=' + str(res['atyp']))

    res['dst_port'] = data.read('uint16')

    return res


def reply_request(rep: int, atyp: int, bnd_addr: str, bnd_port: int) -> bytes:
    data = BitStream()

    data += pack('uint8', VERSION)
    data += pack('uint8', rep)
    data += pack('uint8', 0)
    data += pack('uint8', atyp)

    if atyp == ATYP.IPV4:
        data += pack('bytes4', socket.inet_pton(socket.AF_INET, bnd_addr))
    elif atyp == ATYP.DOMAINNAME:
        length = len(bnd_addr)
        data += pack('uint8', length)
        data += pack('bytes' + str(length), bnd_addr.encode())
    elif atyp == ATYP.IPV6:
        data += pack('bytes16', socket.inet_pton(socket.AF_INET6, bnd_addr))
    else:
        raise RuntimeError('Unknown ATYP=' + str(atyp))

    data += pack('uint16', bnd_port)

    return data.tobytes()
