/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <string.h>

#include <dogecoin/cstr.h>
#include <dogecoin/crypto/common.h>
#include <dogecoin/serialize.h>
#include <dogecoin/utils.h>

/**
 * Append a buffer to a cstring
 * 
 * @param s the cstring to append to
 * @param p The pointer to the data to be serialized.
 * @param len the length of the data to be serialized
 */
void ser_bytes(cstring* s, const void* p, size_t len)
{
    cstr_append_buf(s, p, len);
}

/**
 * Convert a uint16_t to a
 * little-endian byte array and append it to the end of the cstring
 * 
 * @param s the cstring to append to
 * @param v_ The value to be converted to a string.
 */
void ser_u16(cstring* s, uint16_t v_)
{
    uint16_t v = htole16(v_);
    cstr_append_buf(s, &v, sizeof(v));
}

/**
 * Convert a 32-bit unsigned integer to a byte array and append it to a cstring
 * 
 * @param s the cstring to append to
 * @param v_ The value to be serialized.
 */
void ser_u32(cstring* s, uint32_t v_)
{
    uint32_t v = htole32(v_);
    cstr_append_buf(s, &v, sizeof(v));
}

/**
 * Given a cstring pointer and an int32_t value, serialize the value into the cstring
 * 
 * @param s the string to append to
 * @param v_ the variable to serialize
 */
void ser_s32(cstring* s, int32_t v_)
{
    ser_u32(s, (uint32_t)v_);
}

/**
 * Given a cstring and a uint64_t, append the uint64_t to the cstring in little endian format
 * 
 * @param s the cstring to append to
 * @param v_ The value to be serialized.
 */
void ser_u64(cstring* s, uint64_t v_)
{
    uint64_t v = htole64(v_);
    cstr_append_buf(s, &v, sizeof(v));
}

/**
 * Given a cstring pointer and an int64_t value, serialize the value into the cstring
 * 
 * @param s the string to append to
 * @param v_ the value to be serialized
 */
void ser_s64(cstring* s, int64_t v_)
{
    ser_u64(s, (uint64_t)v_);
}

/**
 * It serializes a 256-bit unsigned integer into a cstring.
 * 
 * @param s The string to append the bytes to.
 * @param v_ the value to be serialized
 */
void ser_u256(cstring* s, const unsigned char* v_)
{
    ser_bytes(s, v_, 32);
}

/**
 * Serialize a variable length integer
 * 
 * @param s the cstring to serialize to
 * @param vlen the length of the variable length integer
 */
void ser_varlen(cstring* s, uint32_t vlen)
{
    unsigned char c;

    if (vlen < 253) {
        c = vlen;
        ser_bytes(s, &c, 1);
    }

    else if (vlen < 0x10000) {
        c = 253;
        ser_bytes(s, &c, 1);
        ser_u16(s, (uint16_t)vlen);
    }

    else {
        c = 254;
        ser_bytes(s, &c, 1);
        ser_u32(s, vlen);
    }

    /* u64 case intentionally not implemented */
}

/**
 * Given a string, serialize it as a variable length string
 * 
 * @param s the cstring to serialize to
 * @param s_in the string to be serialized
 * @param maxlen The maximum length of the string.
 */
void ser_str(cstring* s, const char* s_in, size_t maxlen)
{
    size_t slen = strnlen(s_in, maxlen);

    ser_varlen(s, slen);
    ser_bytes(s, s_in, slen);
}

/**
 * Given a cstring, serialize the length of the cstring and then serialize the cstring itself
 * 
 * @param s the cstring to write to
 * @param s_in the input string
 * 
 * @return Nothing.
 */
void ser_varstr(cstring* s, cstring* s_in)
{
    if (!s_in || !s_in->len) {
        ser_varlen(s, 0);
        return;
    }

    ser_varlen(s, s_in->len);
    ser_bytes(s, s_in->str, s_in->len);
}

/**
 * Skip the next `len` bytes in the buffer
 * 
 * @param buf The const_buffer object to be deserialized.
 * @param len The length of the data to be deserialized.
 * 
 * @return The number of bytes skipped.
 */
int deser_skip(struct const_buffer* buf, size_t len)
{
    char* p;
    if (buf->len < len) {
        return false;
    }

    p = (char*)buf->p;
    p += len;
    buf->p = p;
    buf->len -= len;

    return true;
}

/**
 * "Deserialize a buffer into a pointer."
 * 
 * The function takes a pointer to a buffer, a pointer to a buffer, and a length. It copies the length
 * bytes from the buffer into the pointer, and updates the buffer pointer to point to the next byte
 * after the copied bytes
 * 
 * @param po the pointer to the object to deserialize into
 * @param buf The buffer to deserialize into.
 * @param len The length of the data to be deserialized.
 * 
 * @return Nothing.
 */
int deser_bytes(void* po, struct const_buffer* buf, size_t len)
{
    char* p;
    if (buf->len < len) {
        return false;
    }

    memcpy_s(po, buf->p, len);
    p = (char*)buf->p;
    p += len;
    buf->p = p;
    buf->len -= len;

    return true;
}

/**
 * "Deserialize a 16-bit unsigned integer from a buffer."
 * 
 * The function name is deser_u16, which means "deserialize a 16-bit unsigned integer." The function
 * takes two arguments:
 * 
 * vo is a pointer to a 16-bit unsigned integer.
 * buf is a pointer to a const_buffer.
 * The function returns true if it was able to deserialize the integer, and false otherwise
 * 
 * @param vo the variable to store the deserialized value
 * @param buf The const_buffer to read from.
 * 
 * @return Nothing.
 */
int deser_u16(uint16_t* vo, struct const_buffer* buf)
{
    uint16_t v;

    if (!deser_bytes(&v, buf, sizeof(v))) {
        return false;
    }

    *vo = le16toh(v);
    return true;
}

/**
 * "Deserialize a 32-bit integer from a buffer."
 * 
 * The function name is deser_s32, which means "deserialize a 32-bit integer." The function takes two
 * arguments:
 * 
 * vo is a pointer to the integer that will be deserialized.
 * buf is a pointer to the buffer that contains the data to be deserialized.
 * The function returns true if the deserialization was successful, and false otherwise
 * 
 * @param vo the variable to store the deserialized value
 * @param buf The const_buffer to read from.
 * 
 * @return A boolean value.
 */
int deser_s32(int32_t* vo, struct const_buffer* buf)
{
    int32_t v;

    if (!deser_bytes(&v, buf, sizeof(v))) {
        return false;
    }
    *vo = le32toh(v);
    return true;
}

/**
 * "Deserialize a 4 byte unsigned integer from a buffer."
 * 
 * The function name is deser_u32, which means "deserialize an unsigned 32-bit integer."
 * 
 * The function takes two arguments:
 * 
 * vo: The variable to store the deserialized value.
 * buf: The buffer to deserialize from
 * 
 * @param vo the variable to store the deserialized value
 * @param buf the const_buffer to read from
 * 
 * @return A boolean value.
 */
int deser_u32(uint32_t* vo, struct const_buffer* buf)
{
    uint32_t v;

    if (!deser_bytes(&v, buf, sizeof(v))) {
        return false;
    }
    *vo = le32toh(v);
    return true;
}

/**
 * "Deserialize a 64-bit unsigned integer from a buffer."
 * 
 * The function name is deser_u64, which means "deserialize an unsigned 64-bit integer". The function
 * takes two arguments:
 * 
 * vo: The variable to store the deserialized value.
 * buf: The buffer to deserialize from.
 * The function returns true if the deserialization was successful, and false otherwise
 * 
 * @param vo the variable to store the deserialized value
 * @param buf the const_buffer to read from
 * 
 * @return Nothing.
 */
int deser_u64(uint64_t* vo, struct const_buffer* buf)
{
    uint64_t v;

    if (!deser_bytes(&v, buf, sizeof(v))) {
        return false;
    }

    *vo = le64toh(v);
    return true;
}

/**
 * Deser_u256() is a function that takes a uint256 and a const_buffer as arguments. It returns 0 on
 * success and -1 on failure
 * 
 * @param vo the variable to deserialize into
 * @param buf the buffer to deserialize into
 * 
 * @return Nothing.
 */
int deser_u256(uint256 vo, struct const_buffer* buf)
{
    return deser_bytes(vo, buf, 32);
}

/**
 * Deser_varlen()
 * deserializes a variable length integer from a buffer
 * 
 * @param lo the length of the variable-length data
 * @param buf the buffer to read from
 * 
 * @return Nothing.
 */
int deser_varlen(uint32_t* lo, struct const_buffer* buf)
{
    uint32_t len;

    unsigned char c;
    if (!deser_bytes(&c, buf, 1))
        return false;

    if (c == 253) {
        uint16_t v16;
        if (!deser_u16(&v16, buf))
            return false;
        len = v16;
    } else if (c == 254) {
        uint32_t v32;
        if (!deser_u32(&v32, buf))
            return false;
        len = v32;
    } else if (c == 255) {
        uint64_t v64;
        if (!deser_u64(&v64, buf))
            return false;
        printf("\n\n***WARNING: truncate %lu; L192-serialize.c\n\n", (unsigned long)sizeof(v64));
        len = v64; /* WARNING: truncate */
    } else {
        len = c;
    }

    *lo = len;
    return true;
}

/**
 * Read a single byte from the file. 
 * If it's 253, read a 16-bit unsigned integer from the file. 
 * If it's 254, read a 32-bit unsigned integer from the file. 
 * If it's 255, read a 64-bit unsigned integer from the file. 
 * Otherwise, the byte is the length.
 * 
 * @param lo the length of the variable-length data
 * @param file the file to read from
 * 
 * @return Nothing.
 */
int deser_varlen_from_file(uint32_t* lo, FILE* file)
{
    uint32_t len;
    struct const_buffer buf;
    unsigned char c;
    const unsigned char bufp[sizeof(uint64_t)];

    if (fread(&c, 1, 1, file) != 1)
        return false;

    buf.p = (void*)bufp;
    buf.len = sizeof(uint64_t);

    if (c == 253) {
        uint16_t v16;
        if (fread((void*)buf.p, 1, sizeof(v16), file) != sizeof(v16))
            return false;
        if (!deser_u16(&v16, &buf))
            return false;
        len = v16;
    } else if (c == 254) {
        uint32_t v32;
        if (fread((void*)buf.p, 1, sizeof(v32), file) != sizeof(v32))
            return false;
        if (!deser_u32(&v32, &buf))
            return false;
        len = v32;
    } else if (c == 255) {
        uint64_t v64;
        if (fread((void*)buf.p, 1, sizeof(v64), file) != sizeof(v64))
            return false;
        if (!deser_u64(&v64, &buf))
            return false;
        len = (uint32_t)v64; /* WARNING: truncate */
    } else
        len = c;

    *lo = len;
    return true;
}

/**
 * Read a single byte from the file, and if it's one of the special values, read the next byte to get
 * the length. 
 * Otherwise, the length is just the value of the byte.
 * 
 * @param lo the length of the file
 * @param file The file to read from.
 * @param rawdata This is the pointer to the pointer to the buffer to be parsed.
 * @param buflen_inout This is the variable that will store the length of the string.
 * 
 * @return A string.
 */
int deser_varlen_file(uint32_t* lo, FILE* file, uint8_t* rawdata, size_t* buflen_inout)
{
    uint32_t len;
    struct const_buffer buf;
    unsigned char c;
    const unsigned char bufp[sizeof(uint64_t)];

    /* check min size of the buffer */
    if (*buflen_inout < sizeof(len))
        return false;

    if (fread(&c, 1, 1, file) != 1)
        return false;

    rawdata[0] = c;
    *buflen_inout = 1;

    buf.p = (void*)bufp;
    buf.len = sizeof(uint64_t);

    if (c == 253) {
        uint16_t v16;
        if (fread((void*)buf.p, 1, sizeof(v16), file) != sizeof(v16))
            return false;
        memcpy_s(rawdata + 1, buf.p, sizeof(v16));
        *buflen_inout += sizeof(v16);
        if (!deser_u16(&v16, &buf))
            return false;
        len = v16;
    } else if (c == 254) {
        uint32_t v32;
        if (fread((void*)buf.p, 1, sizeof(v32), file) != sizeof(v32))
            return false;
        memcpy_s(rawdata + 1, buf.p, sizeof(v32));
        *buflen_inout += sizeof(v32);
        if (!deser_u32(&v32, &buf))
            return false;
        len = v32;
    } else if (c == 255) {
        uint64_t v64;
        if (fread((void*)buf.p, 1, sizeof(v64), file) != sizeof(v64))
            return false;
        memcpy_s(rawdata + 1, buf.p, sizeof(uint32_t)); /* warning, truncate! */
        *buflen_inout += sizeof(uint32_t);
        if (!deser_u64(&v64, &buf))
            return false;
        len = (uint32_t)v64; /* WARNING: truncate */
    } else {
        len = c;
    }

    *lo = len;
    return true;
}


/**
 * Deserialize a string from a buffer
 * 
 * @param so the string to be deserialized
 * @param buf the buffer to deserialize into
 * @param maxlen The maximum length of the string.
 * 
 * @return Nothing.
 */
int deser_str(char* so, struct const_buffer* buf, size_t maxlen)
{
    uint32_t len;
    uint32_t skip_len = 0;
    if (!deser_varlen(&len, buf)) {
        return false;
    }

    /* if input larger than buffer, truncate copy, skip remainder */
    if (len > maxlen) {
        skip_len = len - maxlen;
        len = maxlen;
    }

    if (!deser_bytes(so, buf, len)) {
        return false;
    }
    if (!deser_skip(buf, skip_len)) {
        return false;
    }

    /* add C string null */
    if (len < maxlen) {
        so[len] = 0;
    }
    else {
        so[maxlen - 1] = 0;
    }

    return true;
}

/**
 * Deser_varstr()
 * deserializes a variable length string from a buffer
 * 
 * @param so The string to be deserialized.
 * @param buf The buffer to deserialize into.
 * 
 * @return A cstring object.
 */
int deser_varstr(cstring** so, struct const_buffer* buf)
{
    uint32_t len;
    cstring* s;
    char* p;

    if (*so) {
        cstr_free(*so, 1);
        *so = NULL;
    }

    if (!deser_varlen(&len, buf))
        return false;

    if (buf->len < len)
        return false;

    s = cstr_new_sz(len);
    cstr_append_buf(s, buf->p, len);

    p = (char*)buf->p;
    p += len;
    buf->p = p;
    buf->len -= len;

    *so = s;

    return true;
}

/**
 * Deser_s64() is a function that takes a pointer to an int64_t and a const_buffer object. It
 * deserializes the const_buffer object into the int64_t pointed to by the pointer
 * 
 * @param vo the variable to deserialize into
 * @param buf the buffer to deserialize from
 * 
 * @return Nothing.
 */
int deser_s64(int64_t* vo, struct const_buffer* buf)
{
    return deser_u64((uint64_t*)vo, buf);
}