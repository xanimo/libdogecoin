/*
 * libFuzzer harness for dogecoin_block_header_deserialize.
 */
#include <stdint.h>
#include <stddef.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/block.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/buffer.h>
#include <dogecoin/arith_uint256.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    dogecoin_block_header *header = dogecoin_block_header_new();
    struct const_buffer buf = { data, size };
    arith_uint256 chainwork = {0};
    dogecoin_block_header_deserialize(header, &buf, &dogecoin_chainparams_main, &chainwork);
    dogecoin_block_header_free(header);
    return 0;
}
