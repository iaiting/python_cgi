from ctypes import CDLL, c_char


def get_cert():
    dll = CDLL("c_/lib_anwei.so")
    cert_list = (c_char * 1024)()
    dll.export_cert(cert_list)
    cert = str(bytes.hex(cert_list.raw).encode("utf-8"), "utf-8")
    return cert


a = get_cert()
print(a)
