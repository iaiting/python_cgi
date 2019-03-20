cmake_minimum_required(VERSION 3.13)
project(src C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(src
        alg_performances.c
        alg_performances.h
        clear_secure_state.c
        CommonType.h
        demo_skf.c
        dev_application_funs.c
        dev_application_funs.h
        dev_container_funs.c
        dev_container_funs.h
        dev_control_funs.c
        dev_control_funs.h
        dev_ecc_funs.c
        dev_ecc_funs.h
        dev_file_funs.c
        dev_file_funs.h
        dev_manage_funs.c
        dev_manage_funs.h
        dev_rsa_funs.c
        dev_rsa_funs.h
        dev_skf_expand_interface.c
        dev_skf_expand_interface.h
        dev_sym_hash_funs.c
        dev_sym_hash_funs.h
        devkey.c
        export_cert.c
        import_cert.c
        skf.h
        test.c
        test_update_firmware.c
        test_update_firmware.h)
