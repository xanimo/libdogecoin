/* Copyright 2022 raffecat
 * Copyright 2022 The Dogecoin Foundation
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <dogecoin/json_out.h>
#include <dogecoin/tx.h>
#include <dogecoin/mem.h>
#include <dogecoin/script.h>
#include <dogecoin/koinu.h>
#include <dogecoin/utils.h>
#include <stddef.h>
#include <inttypes.h>
#include <assert.h>


// Stream abstraction

// Currently implements streaming to memory buffers.

// Note: by changing the private struct members and stream_out functions,
// this abstraction can output to stdio, files, network sockets, etc
// without any change to callers.

#define doge_stream_segment_size (2048 - sizeof(struct doge_stream_segment*))
#define doge_stream_init {NULL, NULL, 0}

typedef struct doge_stream_segment {
    struct doge_stream_segment* next;
    char data[doge_stream_segment_size];
} doge_stream_segment;

// initialise an output stream to memory buffer.
doge_stream doge_stream_new_membuf(uint32_t flags) {
    doge_stream_segment* buf = (doge_stream_segment*) dogecoin_malloc(sizeof(doge_stream_segment));
    buf->next = NULL;
    doge_stream s = { 0, flags, buf, buf, 0 };
    return s;
}

// delete an output stream and free all data.
void doge_stream_free(doge_stream* s) {
    if (!s) return;
    doge_stream_segment* seg = s->head;
    while (seg != NULL) {
        doge_stream_segment* next = seg->next;
        dogecoin_free(seg);
        seg = next;
    }
    s->ofs = 0; s->flags = 0;
    s->head = NULL; s->tail = NULL;
}

void doge_stream_out_n(doge_stream* s, const char* str, size_t n) {
    size_t ofs = s->ofs;
    for (;;) {
        if (ofs + n <= doge_stream_segment_size) {
            // remaining n fits in the current segment (fast path)
            memcpy(s->tail->data + ofs, str, n);
            s->ofs = ofs + n;
            return;
        } else {
            // remaining n exceeds remaining segment space.
            size_t copy = doge_stream_segment_size - ofs;
            assert(copy <= n);
            memcpy(&s->tail->data[ofs], str, copy);
            // consume some of the input.
            n -= copy;
            str += copy;
            // allocate the next segment.
            doge_stream_segment* new_seg = (doge_stream_segment*) dogecoin_malloc(sizeof(doge_stream_segment));
            new_seg->next = NULL;    // this -> NULL
            s->tail->next = new_seg; // prev -> this
            s->tail = new_seg;
            ofs = 0;
        }
    }
}

void doge_stream_out_slice(doge_stream* s, const char* begin, const char* end) {
    ptrdiff_t len = (ptrdiff_t)end - (ptrdiff_t)begin;
    assert(len >= 0);
    doge_stream_out_n(s, begin, len);
}

#define hex_buf_size 32

void doge_stream_out_hex(doge_stream* s, const unsigned char* data, size_t len) {
    char buf[(hex_buf_size*2)+1]; // +1 for '\0' (see utils_bin_to_hex)
    while (len) {
        size_t n = len > hex_buf_size ? hex_buf_size : len;
        utils_bin_to_hex((unsigned char*) data, n, buf);
        doge_stream_out_n(s, buf, n * 2);
        len -= n;
    }
}

cstring* doge_stream_to_cstring(doge_stream* s) {
    doge_stream_segment *span, *last = s->tail;
    size_t len = s->ofs; // length of last segment.
    for (span = s->head; span != last; span = span->next) {
        len += doge_stream_segment_size; // plus a full segment.
    }
    cstring* cs = cstr_new_sz(len);
    for (span = s->head; span != last; span = span->next) {
        cstr_append_buf(cs, span->data, doge_stream_segment_size); // full segment.
    }
    if (s->ofs) {
        cstr_append_buf(cs, last->data, s->ofs); // last segment.
    }
    return cs;
}


// JSON output to stream

#define json_spaces_len 17
static const char* json_spaces = "\n                "; // '\n' + 16 spaces.

static void doge_stream_nl_indent(doge_stream* s) {
    size_t n = 1 + s->depth;
    const char* indent = json_spaces;
    size_t limit = json_spaces_len;
    for (;;) {
        if (n <= limit) {
            doge_stream_out_n(s, indent, n); // fast path.
            return;
        } else {
            // slow path: n > limit.
            doge_stream_out_n(s, indent, limit);
            n -= limit;
            // only output '\n' once.
            indent = json_spaces + 1; // after '\n'
            limit = json_spaces_len - 1; // without '\n'
        }
    }
}

static void doge_json_emit_comma(doge_stream* s) {
    // actually JSON can work by suppressing comma after each open-bracket.
    doge_stream_out_n(s, ",", 1);
    if (s->flags & doge_stream_indent) {
        doge_stream_nl_indent(s);
    }
}

static void doge_json_emit_string(doge_stream* s, const char* value) {
    doge_stream_out_n(s, "\"", 1);
    for (;;) {
        char* quote = strchr(value, '"');
        if (quote) {
            // segment before quote.
            doge_stream_out_slice(s, value, quote);
            doge_stream_out_n(s, "\\\"", 2);
            value = quote + 1;
        } else {
            // final segment.
            doge_stream_out_n(s, value, strlen(value));
            break;
        }
    }
    doge_stream_out_n(s, "\"", 1);
}

void doge_json_out_str(doge_stream* s, const char* value) {
    if (s->flags & doge_stream_need_comma) {
        doge_json_emit_comma(s);
    }
    s->flags |= doge_stream_need_comma; // following values require comma prefix.
    doge_json_emit_string(s, value);
}

void doge_json_out_str_begin(doge_stream* s) {
    if (s->flags & doge_stream_need_comma) {
        doge_json_emit_comma(s);
    }
    s->flags |= doge_stream_need_comma; // following values require comma prefix.
    doge_stream_out_n(s, "\"", 1);
}

void doge_json_out_str_end(doge_stream* s) {
    doge_stream_out_n(s, "\"", 1);
}

void doge_json_out_hex_str(doge_stream* s, const unsigned char* data, size_t len) {
    doge_json_out_str_begin(s);
    doge_stream_out_hex(s, data, len);
    doge_json_out_str_end(s);
}

void doge_json_out_raw(doge_stream* s, char* value) {
    if (s->flags & doge_stream_need_comma) {
        doge_json_emit_comma(s);
    }
    s->flags |= doge_stream_need_comma; // following values require comma prefix.
    doge_stream_out_n(s, value, strlen(value));
}

void doge_json_out_dbl(doge_stream* s, double value) {
    char buf[32]; // 24 are sufficient?
    int len = 0;
    if (s->flags & doge_stream_need_comma) {
        doge_json_emit_comma(s);
    }
    s->flags |= doge_stream_need_comma; // following values require comma prefix.
    snprintf(buf, sizeof(buf), "%f%n", value, &len);
    doge_stream_out_n(s, buf, len);
}

void doge_json_out_int(doge_stream* s, int64_t value) {
    char buf[24]; // INT64_MAX is 19 chars.
    int len = 0;
    if (s->flags & doge_stream_need_comma) {
        doge_json_emit_comma(s);
    }
    s->flags |= doge_stream_need_comma; // following values require comma prefix.
    snprintf(buf, sizeof(buf), "%" PRId64 "%n", value, &len);
    doge_stream_out_n(s, buf, len);
}

void doge_json_out_bool(doge_stream* s, dogecoin_bool value) {
    if (s->flags & doge_stream_need_comma) {
        doge_json_emit_comma(s);
    }
    s->flags |= doge_stream_need_comma; // following values require comma prefix.
    if (value) {
        doge_stream_out_n(s, "true", 4);
    } else {
        doge_stream_out_n(s, "false", 5);
    }
}

void doge_json_out_null(doge_stream* s) {
    if (s->flags & doge_stream_need_comma) {
        doge_json_emit_comma(s);
    }
    s->flags |= doge_stream_need_comma; // following values require comma prefix.
    doge_stream_out_n(s, "null", 4);
}

void doge_json_out_obj_begin(doge_stream* s) {
    if (s->flags & doge_stream_need_comma) {
        doge_json_emit_comma(s);
    }
    doge_stream_out_n(s, "{", 1);
    if (s->flags & doge_stream_indent) {
        s->depth += 2; // increase indent before first key.
        doge_stream_nl_indent(s);
    }
    s->flags &= ~doge_stream_need_comma; // suppress comma before first key.
}

void doge_json_out_obj_key(doge_stream* s, const char* key) {
    if (s->flags & doge_stream_need_comma) {
        doge_json_emit_comma(s);
        s->flags &= ~doge_stream_need_comma; // suppress comma after key.
    }
    doge_json_emit_string(s, key);
    if (s->flags & doge_stream_indent) {
        doge_stream_out_n(s, ": ", 2);
    } else {
        doge_stream_out_n(s, ":", 1);
    }
}

void doge_json_out_obj_end(doge_stream* s) {
    if (s->flags & doge_stream_indent) {
        s->depth -= 2; // decrease indent before closing brace.
        doge_stream_nl_indent(s);
    }
    s->flags |= doge_stream_need_comma; // following values require comma prefix.
    doge_stream_out_n(s, "}", 1);
}

void doge_json_out_arr_begin(doge_stream* s) {
    if (s->flags & doge_stream_need_comma) {
        doge_json_emit_comma(s);
    }
    doge_stream_out_n(s, "[", 1);
    if (s->flags & doge_stream_indent) {
        s->depth += 2; // increase indent before first value.
        doge_stream_nl_indent(s);
    }
    s->flags &= ~doge_stream_need_comma; // suppress comma before first value.
}

void doge_json_out_arr_end(doge_stream* s) {
    if (s->flags & doge_stream_indent) {
        s->depth -= 2; // decrease indent before closing bracket.
        doge_stream_nl_indent(s);
    }
    s->flags |= doge_stream_need_comma; // following values require comma prefix.
    doge_stream_out_n(s, "]", 1);
}



// Script disassembly output to stream

// WARNING: ensure no gaps in the range: 79..185
static const char* op_table[] = {
    // generated by gen-ops.py
    // <length> <space> <TOKEN>
    "\x0b OP_1NEGATE", // 79 0x4f
    "\x0e OP_INVALID_80", // 80 0x50
    "\x05 OP_1", // 81 0x51
    "\x05 OP_2", // 82 0x52
    "\x05 OP_3", // 83 0x53
    "\x05 OP_4", // 84 0x54
    "\x05 OP_5", // 85 0x55
    "\x05 OP_6", // 86 0x56
    "\x05 OP_7", // 87 0x57
    "\x05 OP_8", // 88 0x58
    "\x05 OP_9", // 89 0x59
    "\x06 OP_10", // 90 0x5a
    "\x06 OP_11", // 91 0x5b
    "\x06 OP_12", // 92 0x5c
    "\x06 OP_13", // 93 0x5d
    "\x06 OP_14", // 94 0x5e
    "\x06 OP_15", // 95 0x5f
    "\x06 OP_16", // 96 0x60
    "\x07 OP_NOP", // 97 0x61
    "\x07 OP_VER", // 98 0x62
    "\x06 OP_IF", // 99 0x63
    "\x09 OP_NOTIF", // 100 0x64
    "\x09 OP_VERIF", // 101 0x65
    "\x0c OP_VERNOTIF", // 102 0x66
    "\x08 OP_ELSE", // 103 0x67
    "\x09 OP_ENDIF", // 104 0x68
    "\x0a OP_VERIFY", // 105 0x69
    "\x0a OP_RETURN", // 106 0x6a
    "\x0e OP_TOALTSTACK", // 107 0x6b
    "\x10 OP_FROMALTSTACK", // 108 0x6c
    "\x09 OP_2DROP", // 109 0x6d
    "\x08 OP_2DUP", // 110 0x6e
    "\x08 OP_3DUP", // 111 0x6f
    "\x09 OP_2OVER", // 112 0x70
    "\x08 OP_2ROT", // 113 0x71
    "\x09 OP_2SWAP", // 114 0x72
    "\x09 OP_IFDUP", // 115 0x73
    "\x09 OP_DEPTH", // 116 0x74
    "\x08 OP_DROP", // 117 0x75
    "\x07 OP_DUP", // 118 0x76
    "\x07 OP_NIP", // 119 0x77
    "\x08 OP_OVER", // 120 0x78
    "\x08 OP_PICK", // 121 0x79
    "\x08 OP_ROLL", // 122 0x7a
    "\x07 OP_ROT", // 123 0x7b
    "\x08 OP_SWAP", // 124 0x7c
    "\x08 OP_TUCK", // 125 0x7d
    "\x07 OP_CAT", // 126 0x7e
    "\x0a OP_SUBSTR", // 127 0x7f
    "\x08 OP_LEFT", // 128 0x80
    "\x09 OP_RIGHT", // 129 0x81
    "\x08 OP_SIZE", // 130 0x82
    "\x0a OP_INVERT", // 131 0x83
    "\x07 OP_AND", // 132 0x84
    "\x06 OP_OR", // 133 0x85
    "\x07 OP_XOR", // 134 0x86
    "\x09 OP_EQUAL", // 135 0x87
    "\x0f OP_EQUALVERIFY", // 136 0x88
    "\x0d OP_RESERVED1", // 137 0x89
    "\x0d OP_RESERVED2", // 138 0x8a
    "\x08 OP_1ADD", // 139 0x8b
    "\x08 OP_1SUB", // 140 0x8c
    "\x08 OP_2MUL", // 141 0x8d
    "\x08 OP_2DIV", // 142 0x8e
    "\x0a OP_NEGATE", // 143 0x8f
    "\x07 OP_ABS", // 144 0x90
    "\x07 OP_NOT", // 145 0x91
    "\x0d OP_0NOTEQUAL", // 146 0x92
    "\x07 OP_ADD", // 147 0x93
    "\x07 OP_SUB", // 148 0x94
    "\x07 OP_MUL", // 149 0x95
    "\x07 OP_DIV", // 150 0x96
    "\x07 OP_MOD", // 151 0x97
    "\x0a OP_LSHIFT", // 152 0x98
    "\x0a OP_RSHIFT", // 153 0x99
    "\x0b OP_BOOLAND", // 154 0x9a
    "\x0a OP_BOOLOR", // 155 0x9b
    "\x0c OP_NUMEQUAL", // 156 0x9c
    "\x12 OP_NUMEQUALVERIFY", // 157 0x9d
    "\x0f OP_NUMNOTEQUAL", // 158 0x9e
    "\x0c OP_LESSTHAN", // 159 0x9f
    "\x0f OP_GREATERTHAN", // 160 0xa0
    "\x13 OP_LESSTHANOREQUAL", // 161 0xa1
    "\x16 OP_GREATERTHANOREQUAL", // 162 0xa2
    "\x07 OP_MIN", // 163 0xa3
    "\x07 OP_MAX", // 164 0xa4
    "\x0a OP_WITHIN", // 165 0xa5
    "\x0d OP_RIPEMD160", // 166 0xa6
    "\x08 OP_SHA1", // 167 0xa7
    "\x0a OP_SHA256", // 168 0xa8
    "\x0b OP_HASH160", // 169 0xa9
    "\x0b OP_HASH256", // 170 0xaa
    "\x11 OP_CODESEPARATOR", // 171 0xab
    "\x0c OP_CHECKSIG", // 172 0xac
    "\x12 OP_CHECKSIGVERIFY", // 173 0xad
    "\x11 OP_CHECKMULTISIG", // 174 0xae
    "\x17 OP_CHECKMULTISIGVERIFY", // 175 0xaf
    "\x08 OP_NOP1", // 176 0xb0
    "\x1c OP_NOP2_CHECKLOCKTIMEVERIFY", // 177 0xb1
    "\x08 OP_NOP3", // 178 0xb2
    "\x08 OP_NOP4", // 179 0xb3
    "\x08 OP_NOP5", // 180 0xb4
    "\x08 OP_NOP6", // 181 0xb5
    "\x08 OP_NOP7", // 182 0xb6
    "\x08 OP_NOP8", // 183 0xb7
    "\x08 OP_NOP9", // 184 0xb8
    "\x09 OP_NOP10", // 185 0xb9
};

static const char* op_tpl_ops[] = {
    // template matching params (not valid in script)
    "\x10 OP_SMALLINTEGER", // 250 0xfa
    "\x0b OP_PUBKEYS", // 251 0xfb
    "\x08 OP_0xfc", // 252 0xfc
    "\x0e OP_PUBKEYHASH", // 253 0xfd
    "\x0a OP_PUBKEY", // 254 0xfe
    "\x11 OP_INVALIDOPCODE", // 255 0xff
};

void doge_script_out_asm(doge_stream* s, const unsigned char* script, size_t len) {
    char buf[20]; // maximum is " OP_UNDEFINED_ff\0" (17)
    size_t ofs = 0;
    size_t no_ws = 1;
    if (script[0] == OP_FALSE && script[1] == OP_RETURN) {
        // TODO: special case? following bytes are raw data (dump as hex)
    }
    while (ofs < len) {
        unsigned char op = script[ofs++];
        if (op >= 79) {
            if (op <= 185) {
                // simple opcodes (most common opcodes) - fast path
                const char* token = op_table[op - 79];
                size_t len = (unsigned char)token[0] - no_ws;
                doge_stream_out_n(s, token + 1 + no_ws, len);
                no_ws = 0;
                continue;
            } else if (op >= 250) {
                // template opcodes (not used in scripts) - slow path
                const char* token = op_tpl_ops[op - 250];
                size_t len = (unsigned char)token[0] - no_ws;
                doge_stream_out_n(s, token + 1 + no_ws, len);
                no_ws = 0;
                continue;
            } else {
                // 186..249  0xba..0xf9  Not defined  (not used in scripts) - slow path
                int len = 0;
                sprintf(buf, (char*)" OP_UNDEFINED_%x%n" + no_ws, op, &len);
                doge_stream_out_n(s, buf, len);
                no_ws = 0;
                continue;
            }
        }
        else {
            // Array push opcodes.
            if (op == 0) {
                // 0  0x00  An empty array of bytes is pushed onto the stack.
                doge_stream_out_n(s, (char*)" OP_0" + no_ws, 5 - no_ws);
                no_ws = 0;
                continue;
            }
            else if (op <= 75) {
                // 1..75  0x01..0x4b  An array of N=opcode bytes is pushed onto the stack.
                if (!no_ws) doge_stream_out_n(s, " ", 1);
                doge_stream_out_hex(s, script + ofs, op);
                ofs += op;
                no_ws = 0;
                continue;
            }
            else {
                // 76..78  0x4c..0x4e  The next 1,2,4 bytes contain the size of the array to push onto the stack.
                size_t len = (unsigned char) script[ofs++];
                if (op >= 77) {
                    len = (len << 8) | ((unsigned char) script[ofs++]);
                }
                if (op == 78) {
                    len = (len << 8) | ((unsigned char) script[ofs++]);
                    len = (len << 8) | ((unsigned char) script[ofs++]);
                }
                if (!no_ws) doge_stream_out_n(s, " ", 1);
                doge_stream_out_hex(s, script + ofs, len);
                ofs += len;
                no_ws = 0;
                continue;
            }
        }
    }
}


// Transaction output JSON to stream

static void txn_json_script_sig(doge_stream* s, cstring* script) {
    doge_json_out_obj_begin(s);

    doge_json_out_obj_key(s, "asm");
    doge_json_out_str_begin(s);
    doge_script_out_asm(s, (const unsigned char*)script->str, script->len);
    doge_json_out_str_end(s);

    doge_json_out_obj_key(s, "hex");
    doge_json_out_hex_str(s, (const unsigned char*)script->str, script->len);

    doge_json_out_obj_end(s);
}

static void txn_json_tx_in(doge_stream* s, const dogecoin_tx_in* tx_in) {
    doge_json_out_obj_begin(s);

    doge_json_out_obj_key(s, "txid");
    doge_json_out_hex_str(s, tx_in->prevout.hash, sizeof(tx_in->prevout.hash));

    doge_json_out_obj_key(s, "vout");
    doge_json_out_int(s, tx_in->prevout.n);

    doge_json_out_obj_key(s, "scriptSig");
    txn_json_script_sig(s, tx_in->script_sig);

    doge_json_out_obj_key(s, "sequence");
    doge_json_out_int(s, tx_in->sequence);

    doge_json_out_obj_end(s);
}

static void txn_json_script_pubkey(doge_stream* s, cstring* script) {
    doge_json_out_obj_begin(s);

    doge_json_out_obj_key(s, "asm");
    doge_json_out_str_begin(s);
    doge_script_out_asm(s, (const unsigned char*)script->str, script->len);
    doge_json_out_str_end(s);

    doge_json_out_obj_key(s, "hex");
    doge_json_out_hex_str(s, (const unsigned char*)script->str, script->len);

    // TODO: does core match against script templates?

    // doge_json_out_obj_key(s, "reqSigs");
    // doge_json_out_int(s, 1); // TODO

    // doge_json_out_obj_key(s, "type");
    // doge_json_out_str(s, "pubkeyhash"); // TODO

    // doge_json_out_obj_key(s, "addresses");
    // doge_json_out_arr_begin(s); // TODO
    // doge_json_out_arr_end(s);

    doge_json_out_obj_end(s);
}

static void txn_json_tx_out(doge_stream* s, const dogecoin_tx_out* tx_out, size_t n) {
    // convert value in koinu (int64_t) to dogecoin (decimal string)
    char value[64]; // is 21 enough? ideally define a constant.
    if (!koinu_to_coins_str(tx_out->value, value)) { // how can this fail?!
        value[0] = '0'; value[1] = '\0';
    }

    doge_json_out_obj_begin(s);

    doge_json_out_obj_key(s, "value");
    doge_json_out_raw(s, value);

    // note: libdogecoin addition to decoderawtransaction JSON.
    doge_json_out_obj_key(s, "koinu");
    doge_json_out_int(s, tx_out->value);

    doge_json_out_obj_key(s, "n");
    doge_json_out_int(s, n);

    doge_json_out_obj_key(s, "scriptPubKey");
    txn_json_script_pubkey(s, tx_out->script_pubkey);

    doge_json_out_obj_end(s);
}

void doge_txn_to_json(doge_stream* s, const dogecoin_tx* tx) {

    // calculate the tx hash (txid)
    // ideally: tx should cache this, generate on demand, clear on modify.
    uint256 txhash;
    dogecoin_tx_hash(tx, txhash);

    // calculate the tx size.
    // obviously, this is not great (maybe add an out size_t to dogecoin_tx_hash)
    // ideally: tx should cache this, generate on demand, clear on modify.
    cstring* serialized_transaction = cstr_new_sz(1024);
    dogecoin_tx_serialize(serialized_transaction, tx);
    size_t tx_size = serialized_transaction->len;
    cstr_free(serialized_transaction, true);

    doge_json_out_obj_begin(s);

    doge_json_out_obj_key(s, "txid");
    doge_json_out_hex_str(s, txhash, sizeof(txhash));

    doge_json_out_obj_key(s, "hash");
    doge_json_out_hex_str(s, txhash, sizeof(txhash));

    doge_json_out_obj_key(s, "size");
    doge_json_out_int(s, tx_size);

    doge_json_out_obj_key(s, "vsize");
    doge_json_out_int(s, tx_size);

    doge_json_out_obj_key(s, "version");
    doge_json_out_int(s, tx->version);

    doge_json_out_obj_key(s, "locktime");
    doge_json_out_int(s, tx->locktime);

    doge_json_out_obj_key(s, "vin");
    doge_json_out_arr_begin(s);
    size_t i;
    for (i = 0; i < tx->vin->len; i++) {
        txn_json_tx_in(s, tx->vin->data[i]);
    }
    doge_json_out_arr_end(s);

    doge_json_out_obj_key(s, "vout");
    doge_json_out_arr_begin(s);
    for (i = 0; i < tx->vout->len; i++) {
        txn_json_tx_out(s, tx->vout->data[i], i);
    }
    doge_json_out_arr_end(s);

    doge_json_out_obj_end(s);
}
