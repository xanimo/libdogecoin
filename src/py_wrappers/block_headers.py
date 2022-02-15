from ctypes import *
import os
import helpers as h


#CALLING C FUNCTIONS
def py_dogecoin_block_header_new(lib):
    #creates a new empty block header (all fields initialized to 0)
    lib.dogecoin_block_header_new.restype = c_void_p
    header = c_void_p(lib.dogecoin_block_header_new())
    return header

def py_dogecoin_block_header_deserialize(lib, header_ser, ilen, header_ptr):
    #puts information from buf into header
    lib.dogecoin_block_header_new.restype = c_int32
    if not lib.dogecoin_block_header_deserialize(header_ser, ilen, header_ptr):
        print("wrappers.py: deserialization failed!\n")

def py_dogecoin_block_header_serialize(lib, cstr_ptr, header_ptr):
    #given non-empty block header, translate info into cstring pointer
    lib.dogecoin_block_header_new.restype = None
    lib.dogecoin_block_header_serialize(cstr_ptr, header_ptr)

def py_dogecoin_block_header_copy(lib, new_header_ptr, old_header_ptr):
    #given existing block header, copy information to a new block header
    lib.dogecoin_block_header_copy.restype = None
    lib.dogecoin_block_header_copy(new_header_ptr, old_header_ptr)

def py_dogecoin_block_header_free(lib, header_ptr):
    #given existing block header, set to zero and free the memory allocated for that header
    # Why memset if going to be freed? Not all bits stay at zero after free
    lib.dogecoin_block_header_free.restype = None
    lib.dogecoin_block_header_free(header_ptr)

def py_dogecoin_block_header_hash(lib, header_ptr, hash_ptr):
    #calculate and store the hash of a given block header
    lib.dogecoin_block_header_hash.restype = c_byte
    lib.dogecoin_block_header_hash(header_ptr, hash_ptr)



#STATIC METHODS
def print_dogecoin_block_header_data(header_ptr):
    #given a Dogecoin_block_header pointer, prints out header information
    header = cast(header_ptr, POINTER(h.Dogecoin_block_header)).contents
    pb = bytes(header.prev_block)
    mr = bytes(header.merkle_root)
    print("=====================================================================================")
    print("Version:".ljust(20, " "),        header.version)
    print("Previous block:".ljust(20, " "), pb.hex())
    print("Merkle root:".ljust(20, " "),    mr.hex())
    print("Timestamp:".ljust(20, " "),      header.timestamp)
    print("Bits:".ljust(20, " "),           header.bits)
    print("Nonce".ljust(20, " "),           header.nonce)
    print("=====================================================================================\n\n")

def print_cstring_data(cstring):
    #given a Cstring object, prints out string/mem information
    raw_bytes = bytes((c_byte*cstring.len).from_address(cstring.str))
    print("=====================================================================================")
    print("Serialized string:".ljust(25, " "),         raw_bytes.hex())
    print("Length (bytes):".ljust(25, " "),            cstring.len)
    print("Memory allocated (bytes):".ljust(25, " "),  cstring.alloc)
    print("=====================================================================================\n\n")

def build_byte_string(v, pb, mr, t, b, n):
    #package the information to be put on the block into a bytes object
    b_string = bytes()
    b_string += v.to_bytes(4, 'little')
    b_string += bytes.fromhex(pb)
    b_string += bytes.fromhex(mr)
    b_string += t.to_bytes(4, 'little')
    b_string += b.to_bytes(4, 'little')
    b_string += n.to_bytes(4, 'little')
    return b_string

def print_uint256_hash(hash):
    print(bytes(hash.value).hex())


#MAIN METHOD
if __name__ == "__main__":
    #define testing parameters
    version = 1
    prev_block = "aaaabbbbccccddddeeeeffff00001111aaaabbbbccccddddeeeeffff00001111"
    merkle_root = "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01"
    timestamp = 1644269042
    bits = 0
    nonce = 2

    #import shared library
    libdoge = h.get_lib("libdogecoin.so")

    #test dogecoin_block_header_new
    print("creating a new block header...")
    block_header_ptr = py_dogecoin_block_header_new(libdoge)
    print_dogecoin_block_header_data(block_header_ptr)

    #test dogecoin_block_header_deserialize
    print("writing info to block header...")
    b_str = build_byte_string(version, prev_block, merkle_root, timestamp, bits, nonce)
    header_ser = c_char_p(b_str)
    ilen = len(b_str)
    py_dogecoin_block_header_deserialize(libdoge, header_ser, ilen, block_header_ptr)
    print_dogecoin_block_header_data(block_header_ptr)

    #test dogecoin_block_header_serialize
    print("serializing block header into cstring struct...")
    c_str = h.Cstring()
    py_dogecoin_block_header_serialize(libdoge, byref(c_str), block_header_ptr)
    print_cstring_data(c_str)

    #test dogecoin_block_header_copy
    print("copying block header (displaying copy)...")
    block_header_ptr2 = py_dogecoin_block_header_new(libdoge)
    py_dogecoin_block_header_copy(libdoge, block_header_ptr2, block_header_ptr)
    print_dogecoin_block_header_data(block_header_ptr2)
    
    #test dogecoin_block_header_free
    print("freeing block header...")
    py_dogecoin_block_header_free(libdoge, block_header_ptr)
    print_dogecoin_block_header_data(block_header_ptr)

    #test dogecoin_block_header_hash
    print("hashing block header...")
    hash_obj = h.Uint256()
    py_dogecoin_block_header_hash(libdoge, block_header_ptr, byref(hash_obj))
    print_uint256_hash(hash_obj)