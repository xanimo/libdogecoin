from ctypes import *
import sys
import os

# LOAD SHARED LIBRARY - there has to be a better way to do this
dogepath = os.path.abspath(__file__+"../../../../.libs")
sys.path.insert(0, dogepath)
dogepath = os.path.join(dogepath, "libdogecoin.so")

cdll.LoadLibrary(dogepath)
libdoge = CDLL(dogepath)

# MIMIC C STRUCTS
class Dogecoin_chain(Structure):
    _fields_ = [
        ("chainname",                   c_char * 32),
        ("b58prefix_pubkey_address",    c_byte),
        ("b58prefix_script_address",    c_byte),
        ("b58prefix_secret_address",    c_byte),
        ("b58prefix_bip32_privkey",     c_uint32),
        ("b58prefix_bip32_pubkey",      c_uint32),
        ("netmagic",                    c_ubyte * 4),
    ]

# CALL C FUNCTIONS FROM SHARED LIBRARY
def py_gen_privkey():

    #init constants from chain.h
    byte_buf = (c_ubyte * 4)()
    byte_buf[:] = [0xc0, 0xc0, 0xc0, 0xc0]
    main = Dogecoin_chain(bytes("main", 'utf-8'), 0x1E, 0x16, 0x9E, 0x02fac398, 0x02facafd, byte_buf)
    byte_buf[:] = [0xfc, 0xc1, 0xb7, 0xdc]
    test = Dogecoin_chain(bytes("testnet3", 'utf-8'), 0x71, 0xc4, 0xf1, 0x04358394, 0x043587cf, byte_buf)
    byte_buf[:] = [0xfa, 0xbf, 0xb5, 0xda]
    reg = Dogecoin_chain(bytes("regtest", 'utf-8'), 0x6f, 0xc4, 0xEF, 0x04358394, 0x043587CF, byte_buf)

    #call dogecoin_ecc_start() and gen_privkey()
    libdoge.dogecoin_ecc_start()
    libdoge.gen_privatekey.restype = c_bool
    sizeout = 128
    newprivkey_wif = (c_char*sizeout)()
    newprivkey_hex = (c_char*sizeout)()
    libdoge.gen_privatekey(byref(main), newprivkey_wif, sizeout, newprivkey_hex)
    print("private key wif", str(bytes(newprivkey_wif).decode('utf-8')))
    print("private key hex:", str(bytes(newprivkey_hex).decode('utf-8')))




# MAIN METHODS
if __name__ == "__main__":
    print("======================================================================")
    print("Press [q] to quit CLI\n")
    inp = input("$ ").split()
    while inp != ['q']:
        cmd = inp[0]
        flags = inp[1:]
        if cmd == "gen_privkey":
            py_gen_privkey()
        else:
            print(cmd+": not a valid command")
        print()
        inp = input("$ ").split()
