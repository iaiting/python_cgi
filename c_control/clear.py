from ctypes import CDLL


def clear():
    dll = CDLL("c_/lib_anwei.so")
    dll.clear()


clear()
