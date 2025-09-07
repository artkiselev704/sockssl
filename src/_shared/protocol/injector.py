from bitstring import BitStream, pack

VERSION = 0x01
ENCODING = 'utf-8'


def do_handshake(password: str, dst_addr: str, dst_port: int) -> bytes:
    data = BitStream()

    data += pack('uint8', VERSION)

    length = len(password)
    data += pack('uint8', length)
    data += pack('bytes' + str(length), password.encode(ENCODING))

    length = len(dst_addr)
    data += pack('uint8', length)
    data += pack('bytes' + str(length), dst_addr.encode(ENCODING))

    data += pack('uint16', dst_port)

    return data.tobytes()


def get_handshake(data: bytes) -> dict:
    res = {}
    data = BitStream(data)

    res['version'] = data.read('uint8')
    res['password'] = data.read('bytes' + str(data.read('uint8'))).decode('utf-8')
    res['dst_addr'] = data.read('bytes' + str(data.read('uint8'))).decode('utf-8')
    res['dst_port'] = data.read('uint16')

    return res
