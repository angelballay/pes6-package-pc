"""Versión de un .dll o .exe de Windows, leída del VS_FIXEDFILEINFO del recurso de versión (PUB-4)."""
import struct

_SIG = b'\xbd\x04\xef\xfe'  # 0xFEEF04BD
_KEY = 'VS_VERSION_INFO'.encode('utf-16-le')


def read_versions(blob: bytes):
    """Devuelve (FileVersion, ProductVersion) como tuplas de 4 números, o None si no hay recurso de versión."""
    pos = blob.find(_KEY)
    while pos >= 0:
        sig = blob.find(_SIG, pos, pos + 128)
        if sig >= 0 and sig + 52 <= len(blob):
            _, struc, fms, fls, pms, pls = struct.unpack_from('<6I', blob, sig)
            if struc in (0x00010000, 0):
                return ((fms >> 16, fms & 0xFFFF, fls >> 16, fls & 0xFFFF),
                        (pms >> 16, pms & 0xFFFF, pls >> 16, pls & 0xFFFF))
        pos = blob.find(_KEY, pos + 1)
    return None
