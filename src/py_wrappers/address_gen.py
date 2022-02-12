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



# HELPER METHODS
def get_chain(code=0):
    byte_buf = (c_ubyte * 4)()
    
    # main
    if code==0:
        byte_buf[:] = [0xc0, 0xc0, 0xc0, 0xc0]
        return Dogecoin_chain(bytes("main", 'utf-8'), 0x1E, 0x16, 0x9E, 0x02fac398, 0x02facafd, byte_buf)
        
    # testnet
    elif code==1:           
        byte_buf[:] = [0xfc, 0xc1, 0xb7, 0xdc]
        return Dogecoin_chain(bytes("testnet3", 'utf-8'), 0x71, 0xc4, 0xf1, 0x04358394, 0x043587cf, byte_buf)

    # regtest
    elif code==2:
        byte_buf[:] = [0xfa, 0xbf, 0xb5, 0xda]
        return Dogecoin_chain(bytes("regtest", 'utf-8'), 0x6f, 0xc4, 0xEF, 0x04358394, 0x043587CF, byte_buf)

    else:
        print("Bad chain code provided\n")



# CALL C FUNCTIONS FROM SHARED LIBRARY
def py_gen_privkey(chain_code):

    #init constants from chain.h... 0=main, 1=testnet, 2=regtest
    chain = get_chain(chain_code)

    #prepare arguments
    sizeout = 128
    newprivkey_wif = (c_char*sizeout)()
    newprivkey_hex = (c_char*sizeout)()

    #call gen_privatekey()
    libdoge.gen_privatekey.restype = c_bool
    libdoge.dogecoin_ecc_start()
    libdoge.gen_privatekey(byref(chain), newprivkey_wif, sizeout, newprivkey_hex)
    
    #print result of function
    print("private key wif", str(bytes(newprivkey_wif).decode('utf-8')))
    print("private key hex:", str(bytes(newprivkey_hex).decode('utf-8')))


def py_pubkey_from_privatekey(pkey_wif):

    #identify chain - is this method safe?
    if pkey_wif[0]=='Q':
        chain = get_chain(0)
    elif pkey_wif[0]=='c' and pkey_wif[1].isLowercase():
        chain = get_chain(1)
    elif pkey_wif[0]=='c' and pkey_wif[1].isUppercase():
        chain = get_chain(2)
    else:
        print(cmd+": private key must be WIF encoded")
        return

    #prepare arguments
    pkey = c_char_p(pkey_wif.encode('utf-8'))
    sz = 128
    sizeout = c_ulong(sz)
    pubkey_hex = (c_char * sz)()

    #call pubkey_from_privatekey()
    libdoge.pubkey_from_privatekey.restype = c_bool
    libdoge.pubkey_from_privatekey(byref(chain), pkey, byref(pubkey_hex), byref(sizeout))
    
    #print result of function
    print("public key hex:", str(bytes(pubkey_hex).decode('utf-8')))


def py_address_from_pubkey(chain_code, pubkey_hex):
    
    #init constants from chain.h (0=main, 1=testnet, 2=regtest)
    chain = get_chain(chain_code)

    #prepare arguments
    pubkey = c_char_p(pubkey_hex.encode('utf-8'))
    address = (c_char * 40)() # temporary fix, want c_char_p but causes segfault

    #call address_from_pubkey()
    libdoge.address_from_pubkey.restype = c_bool
    libdoge.address_from_pubkey(byref(chain), pubkey, byref(address))

    #print result from function
    print("dogecoin address:", str(bytes(address).decode('utf-8')))




# MAIN METHOD
if __name__ == "__main__":
    cmd_lst = ["gen_privkey <which_chain>",
               "gen_pubkey <privkey_wif>",
               "gen_address <which_chain> <pubkey_hex>"]
    print("======================================================================")
    print("Press [q] to quit CLI")
    print("Press [w] to repeat previous command\n")
    print("Available commands:\n")
    for c in cmd_lst:
        print(f'\t{c}')
    print("\n")

    inp = input("$ ").split()
    while inp != ['q']:
        if inp[0]=='w':
            pass
        else:
            cmd = inp[0]
        args = inp[1:]
        if cmd == "gen_privkey":
            if args and int(args[0])>=0 and int(args[0])<=2:
                py_gen_privkey(int(args[0]))
            else:
                print(cmd+": enter valid chain code (0:main, 1:test, 2:regtest)")
        elif cmd == "gen_pubkey":
            if args and len(args[0]) >= 50:
                py_pubkey_from_privatekey(args[0])
            else:
                print(cmd+": private key must be WIF encoded")
        elif cmd == "gen_address":
            if args and int(args[0])>=0 and int(args[0])<=2 and len(args[1])==66:
                py_address_from_pubkey(int(args[0]), args[1])
            else:
                print(cmd+": enter valid chain code (0:main, 1:test, 2:regtest)")
        else:
            print(cmd+": not a valid command")
        print()
        inp = input("$ ").split()
