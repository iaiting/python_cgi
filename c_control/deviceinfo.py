from ctypes import CDLL, c_char
import configparser


def read_ini():
    cfg = configparser.ConfigParser()
    cfg.read("config/config.ini")
    return cfg


def devinfo():
    dll = CDLL("c_/lib_anwei.so")
    devinfo_list = (c_char * 118)()
    dll.get_devinfo(devinfo_list)
    raw_list = str(devinfo_list.raw).split("\\")
    data_list = []
    for i in range(0, len(raw_list)):
        if len(raw_list[i]) > 6:
            data_list.append(raw_list[i])
    serial = data_list[0].replace("b'", "")
    cryptovender = data_list[1].replace("x00", "")
    cryptomodcode = data_list[2].replace("x00", "").replace("'", "")
    return serial, cryptovender, cryptomodcode


def final_data(serial, cryptovender, cryptomodcode):
    cfg = read_ini()
    dict_data = {
        "vender": cfg.get("data", "vender"),
        "manufacturer": cfg.get("data", "manufacturer"),
        "factory": cfg.get("data", "factory"),
        "factoryid": cfg.get("data", "factoryid"),
        "product": cfg.get("data", "product"),
        "type": cfg.get("data", "type"),
        "model": cfg.get("data", "model"),
        "initdate": cfg.get("data", "initdate"),
        "level": cfg.get("data", "level"),
        "batch": cfg.get("data", "batch"),
        "serial": serial,
        "cryptovender": cryptovender,
        "cryptomodcode": cryptomodcode,
        "devid": "110108800391320123456",
        "platid": "110108800392000654321"
    }
    return dict_data


serial, cryptovender, cryptomodcode = devinfo()
data = final_data(serial, cryptovender, cryptomodcode)
print(data)
