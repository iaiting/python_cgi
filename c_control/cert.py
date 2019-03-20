from ctypes import CDLL, c_char
import random


def yield_data(cert):
    for c in cert:
        yield int(c)


random_str = ""
for x in range(0, 1024):
    random_str += str(random.randint(1, 9))
print(len(random_str))
gen = yield_data(random_str)


def cert():
    dll = CDLL("c_/lib_anwei.so")
    cert_list = (c_char * 1024)()
    for i in range(0, len(cert_list)):
        cert_list[i] = next(gen)
    dll.import_cert(cert_list)


cert()
