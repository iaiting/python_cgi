#!/bin/sh
arm-openwrt-linux-gcc dev_info.c devkey.c export_cert.c clear_secure_state.c import_cert.c -o arm_lib_anwei.so -shared -fPIC -L. -lSKF_final -L /home/niushuaibing/anwei/toolchain-arm_cortex-a9+neon_gcc-4.8-linaro_uClibc-0.9.33.2_eabi/lib
