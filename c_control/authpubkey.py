from ctypes import CDLL, c_char
import base64


def authpubkey():
    dll = CDLL("c_/lib_anwei.so")
    ecc_list = (c_char * 128)()
    dll.eccpublickey(ecc_list)
    b64_eccpubkey = str(base64.b64encode(bytes.hex(ecc_list.raw).encode("utf-8")), "utf-8")
    return b64_eccpubkey


a = authpubkey()
print(a)
