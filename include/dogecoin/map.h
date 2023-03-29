#ifndef __LIBDOGECOIN_MAP_H__
#define __LIBDOGECOIN_MAP_H__

#include <dogecoin/dogecoin.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SWIG
struct dogecoin_map;
typedef void *dogecoin_map_verify_fn_t;
#else

/** A function to validate a map item */
typedef int (*dogecoin_map_verify_fn_t)(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *value,
    size_t value_len);

/** A map item */
struct dogecoin_map_item {
    unsigned char *key; /* Pointer to the key data, or NULL if the key is an integer */
    size_t key_len; /* Length of key, or the integer key if the key is an integer */
    unsigned char *value;
    size_t value_len;
};

/** A map of integer or byte buffer key, to byte buffer value pairs */
struct dogecoin_map {
    struct dogecoin_map_item *items;
    size_t num_items;
    size_t items_allocation_len;
    dogecoin_map_verify_fn_t verify_fn;
};
#endif /* SWIG */

/**
 * Initialize a new map.
 *
 * :param allocation_len: The number of items to allocate space for.
 * :param verify_fn: A function to verify items before storing, or NULL.
 * :param output: Map to initialize.
 */
LIBDOGECOIN_API int dogecoin_map_init(
    size_t allocation_len,
    dogecoin_map_verify_fn_t verify_fn,
    struct dogecoin_map *output);

/**
 * Allocate and initialize a new map.
 *
 * :param allocation_len: The number of items to allocate space for.
 * :param verify_fn: A function to verify items before storing, or NULL.
 * :param output: Destination for the new map.
 */
LIBDOGECOIN_API int dogecoin_map_init_alloc(
    size_t allocation_len,
    dogecoin_map_verify_fn_t verify_fn,
    struct dogecoin_map **output);

#ifndef SWIG_PYTHON
/**
 * Free a map allocated by `dogecoin_map_init_alloc`.
 *
 * :param map_in: The map to free.
 */
LIBDOGECOIN_API int dogecoin_map_free(
    struct dogecoin_map *map_in);
#endif /* SWIG_PYTHON */

/**
 * Remove all entries from a map.
 *
 * :param map_in: The map to clear.
 *
 * .. note:: This function frees all pre-allocated memory, and thus can
 *|    be used to free a map initialised with `dogecoin_map_init` without
 *|    freeing the map struct itself.
 */
LIBDOGECOIN_API int dogecoin_map_clear(
    struct dogecoin_map *map_in);

/**
 * Add an item to a map.
 *
 * :param map_in: The map to add to.
 * :param key: The key to add.
 * :param key_len: Length of ``key`` in bytes.
 * :param value: The value to add.
 * :param value_len: Length of ``value`` in bytes.
 *
 * .. note:: If the key given is already in the map, this call succeeds
 *|    without altering the map.
 */
LIBDOGECOIN_API int dogecoin_map_add(
    struct dogecoin_map *map_in,
    const unsigned char *key,
    size_t key_len,
    const unsigned char *value,
    size_t value_len);

/**
 * Add an item to a map keyed by an integer.
 *
 * As per `dogecoin_map_add`, using an integer key.
 */
LIBDOGECOIN_API int dogecoin_map_add_integer(
    struct dogecoin_map *map_in,
    uint32_t key,
    const unsigned char *value,
    size_t value_len);

/**
 * Add an item to a map, replacing it if already present.
 *
 * See `dogecoin_map_add`.
 */
LIBDOGECOIN_API int dogecoin_map_replace(
    struct dogecoin_map *map_in,
    const unsigned char *key,
    size_t key_len,
    const unsigned char *value,
    size_t value_len);

/**
 * Add an item to a map keyed by an integer, replacing it if already present.
 *
 * See `dogecoin_map_add_integer`.
 */
LIBDOGECOIN_API int dogecoin_map_replace_integer(
    struct dogecoin_map *map_in,
    uint32_t key,
    const unsigned char *value,
    size_t value_len);

/**
 * Remove an item from a map.
 *
 * :param map_in: The map to remove from.
 * :param key: The key to add.
 * :param key_len: Length of ``key`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_map_remove(
    struct dogecoin_map *map_in,
    const unsigned char *key,
    size_t key_len);

/**
 * Remove an item from a map keyed by an integer.
 *
 * See `dogecoin_map_remove_integer`.
 */
LIBDOGECOIN_API int dogecoin_map_remove_integer(
    struct dogecoin_map *map_in,
    uint32_t key);

/**
 * Find an item in a map from a given position onwards.
 *
 * :param map_in: The map to find ``key`` in.
 * :param index: The zero-based index of the item to start searching from.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
LIBDOGECOIN_API int dogecoin_map_find_from(
    const struct dogecoin_map *map_in,
    size_t index,
    const unsigned char *key,
    size_t key_len,
    size_t *written);

/**
 * Find an item in a map.
 *
 * :param map_in: The map to find ``key`` in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
LIBDOGECOIN_API int dogecoin_map_find(
    const struct dogecoin_map *map_in,
    const unsigned char *key,
    size_t key_len,
    size_t *written);

/**
 * Find an item in a map keyed by an integer.
 *
 * As per `dogecoin_map_find`, using an integer key.
 */
LIBDOGECOIN_API int dogecoin_map_find_integer(
    const struct dogecoin_map *map_in,
    uint32_t key,
    size_t *written);

#ifndef SWIG
/**
 * Find an item in a map.
 *
 * :param map_in: The map to find ``key`` in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 *
 * .. note:: This is a non-standard call for low-level use. It returns the
 *|    map item directly without copying, or NULL if not found/an error occurs.
 */
LIBDOGECOIN_API const struct dogecoin_map_item *dogecoin_map_get(
    const struct dogecoin_map *map_in,
    const unsigned char *key,
    size_t key_len);

/**
 * Find an item in a map keyed by an integer.
 *
 * As per `dogecoin_map_get`, using an integer key.
 */
LIBDOGECOIN_API const struct dogecoin_map_item *dogecoin_map_get_integer(
    const struct dogecoin_map *map_in,
    uint32_t key);
#endif

/**
 * Get the number of key/value items in a map.
 *
 * :param map_in: The map to return the number of items from.
 * :param written: Destination for the number of items.
 */
LIBDOGECOIN_API int dogecoin_map_get_num_items(
    const struct dogecoin_map *map_in,
    size_t *written);

/**
 * Get the length of an items key in a map.
 *
 * :param map_in: The map to return the items key length from.
 * :param index: The zero-based index of the item whose key length to return.
 * :param written: Destination for the length of the items key in bytes.
 *
 * .. note:: Returns 0 if the items key is an integer.
 */
LIBDOGECOIN_API int dogecoin_map_get_item_key_length(
    const struct dogecoin_map *map_in,
    size_t index,
    size_t *written);

/**
 * Return an items key from a map.
 *
 * :param map_in: The map to return the items key from.
 * :param index: The zero-based index of the item whose key to return.
 * :param bytes_out: Destination for the resulting data.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 *
 * .. note:: Returns `DOGECOIN_ERROR` if the items key is an integer.
 */
LIBDOGECOIN_API int dogecoin_map_get_item_key(
    const struct dogecoin_map *map_in,
    size_t index,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Return an items integer key from a map.
 *
 * :param map_in: The map to return the items key from.
 * :param index: The zero-based index of the item whose key to return.
 * :param written: Destination for the items integer key.
 *
 * .. note:: Returns `DOGECOIN_ERROR` if the items key is not an integer.
 */
LIBDOGECOIN_API int dogecoin_map_get_item_integer_key(
    const struct dogecoin_map *map_in,
    size_t index,
    size_t *written);

/**
 * Get the length of an item in a map.
 *
 * :param map_in: The map to return the item length from.
 * :param index: The zero-based index of the item whose length to return.
 * :param written: Destination for the length of the item in bytes.
 */
LIBDOGECOIN_API int dogecoin_map_get_item_length(
    const struct dogecoin_map *map_in,
    size_t index,
    size_t *written);

/**
 * Return an item from a map.
 *
 * :param map_in: The map to return the item from.
 * :param index: The zero-based index of the item to return.
 * :param bytes_out: Destination for the resulting data.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
LIBDOGECOIN_API int dogecoin_map_get_item(
    const struct dogecoin_map *map_in,
    size_t index,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Sort the items in a map.
 *
 * :param map_in: The map to sort.
 * :param flags: Flags controlling sorting. Must be 0.
 */
LIBDOGECOIN_API int dogecoin_map_sort(
    struct dogecoin_map *map_in,
    uint32_t flags);

/**
 * Combine the items from a source map into another map.
 *
 * :param map_in: the destination to combine into.
 * :param source: the source to copy items from.
 *
 * .. note:: If this call fails, ``map_in`` may be left partially updated.
 */
LIBDOGECOIN_API int dogecoin_map_combine(
    struct dogecoin_map *map_in,
    const struct dogecoin_map *source);

/**
 * Replace a maps contents with another map.
 *
 * :param map_in: the destination to combine into.
 * :param source: the source to copy items from.
 *
 * .. note:: If this call fails, ``map_in`` is left untouched.
 */
LIBDOGECOIN_API int dogecoin_map_assign(
    struct dogecoin_map *map_in,
    const struct dogecoin_map *source);

/**
 * Find an item in a public-key keyed map given a BIP32 derived key.
 *
 * :param map_in: The map to find the public key of ``hdkey`` in.
 * :param index: The zero-based index of the item to start searching from.
 * :param hdkey: The BIP32 key to find.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 *
 * .. note:: This function searches for the compressed, x-only and then
 *|    uncompressed public keys, in order. The caller can determine which
 *|    by checking the length of the map item when an item is found.
 */
LIBDOGECOIN_API int dogecoin_map_find_bip32_public_key_from(
    const struct dogecoin_map *map_in,
    size_t index,
    const struct ext_key *hdkey,
    size_t *written);

/**
 * Return a BIP32 derived key matching the keypath of a parent in a map.
 *
 * :param map_in: The map to search for derived keys of ``hdkey`` in.
 * :param index: The zero-based index of the item to start searching from.
 * :param hdkey: The BIP32 parent key to derive matches from.
 * :param output: Destination for the resulting derived key, if any.
 *
 * .. note:: This function searches for keys in the map that are children
 *|    of ``hdkey``. If one is found, the resulting privately derived key
 *|    is returned. If no key is found, ``*output`` is set to ``NULL`` and
 *|    `DOGECOIN_OK` is returned.
 */
LIBDOGECOIN_API int dogecoin_map_keypath_get_bip32_key_from_alloc(
    const struct dogecoin_map *map_in,
    size_t index,
    const struct ext_key *hdkey,
    struct ext_key **output);

/**
 * Verify a PSBT keypath keyed by a serialized bip32 extended public key.
 *
 * :param key: An extended public key in bip32 format.
 * :param key_len: Length of ``key`` in bytes. Must be `BIP32_SERIALIZED_LEN`.
 * :param val: The 4 byte PSBT serialized master key fingerprint followed by the serialized path.
 * :param val_len: Length of ``val`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_keypath_bip32_verify(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *val,
    size_t val_len);

/**
 * Verify a PSBT keypath keyed by a compressed or uncompressed public key.
 *
 * :param key: Public key bytes.
 * :param key_len: Length of ``key`` in bytes. Must be `EC_PUBLIC_KEY_UNCOMPRESSED_LEN` or `BIP32_SERIALIZED_LEN`.
 * :param val: The 4 byte PSBT serialized master key fingerprint followed by the serialized path.
 * :param val_len: Length of ``val`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_keypath_public_key_verify(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *val,
    size_t val_len);

/**
 * Verify a PSBT keypath keyed by an x-only public key.
 *
 * :param key: Public key bytes.
 * :param key_len: Length of ``key`` in bytes. Must be `EC_XONLY_PUBLIC_KEY_LEN`,
 * :param val: The 4 byte PSBT serialized master key fingerprint followed by the serialized path.
 * :param val_len: Length of ``val`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_keypath_xonly_public_key_verify(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *val,
    size_t val_len);

/**
 * Allocate and initialize a new BIP32 keypath map.
 *
 * :param allocation_len: The number of items to allocate space for.
 * :param output: Destination for the new map.
 */
LIBDOGECOIN_API int dogecoin_map_keypath_bip32_init_alloc(
    size_t allocation_len,
    struct dogecoin_map **output);

/**
 * Allocate and initialize a new public key keypath map.
 *
 * :param allocation_len: The number of items to allocate space for.
 * :param output: Destination for the new map.
 */
LIBDOGECOIN_API int dogecoin_map_keypath_public_key_init_alloc(
    size_t allocation_len,
    struct dogecoin_map **output);

/**
 * Convert and add a public key and path to a keypath map.
 *
 * :param map_in: The keypath map to add to.
 * :param pub_key: The public key or extended public key to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be `BIP32_SERIALIZED_LEN`
 *|    for an extended bip32 public key, or `EC_PUBLIC_KEY_UNCOMPRESSED_LEN`
 *|    or `EC_PUBLIC_KEY_LEN` for a public key.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be `BIP32_KEY_FINGERPRINT_LEN`.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
LIBDOGECOIN_API int dogecoin_map_keypath_add(
    struct dogecoin_map *map_in,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

/**
 * Get the key fingerprint from a PSBT keypath's serialized value.
 *
 * :param val: The serialized keypath value as stored in a keypath map.
 * :param val_len: Length of ``val`` in bytes.
 * :param bytes_out: Destination for the fingerprint.
 * FIXED_SIZED_OUTPUT(len, bytes_out, BIP32_KEY_FINGERPRINT_LEN)
 */
LIBDOGECOIN_API int dogecoin_keypath_get_fingerprint(
    const unsigned char *val,
    size_t val_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Return an item's key fingerprint from a keypath map.
 *
 * :param map_in: The map to return the item's fingerprint from.
 * :param index: The zero-based index of the item whose key fingerprint to return.
 * :param bytes_out: Destination for the resulting data.
 * FIXED_SIZED_OUTPUT(len, bytes_out, BIP32_KEY_FINGERPRINT_LEN)
 *
 * .. note:: The same key fingerprint may be present in a keypath map more than once.
 */
LIBDOGECOIN_API int dogecoin_map_keypath_get_item_fingerprint(
    const struct dogecoin_map *map_in,
    size_t index,
    unsigned char *bytes_out,
    size_t len);

/**
 * Get the path length from a PSBT keypath's serialized value.
 *
 * :param val: The serialized keypath value as stored in a keypath map.
 * :param val_len: Length of ``val`` in bytes.
 * :param written: Destination for the items path length.
 */
LIBDOGECOIN_API int dogecoin_keypath_get_path_len(
    const unsigned char *val,
    size_t val_len,
    size_t *written);

/**
 * Get the length of an item's key path from a keypath map.
 *
 * :param map_in: The map to return the item's path length from.
 * :param index: The zero-based index of the item whose path length to return.
 * :param written: Destination for the items path length.
 */
LIBDOGECOIN_API int dogecoin_map_keypath_get_item_path_len(
    const struct dogecoin_map *map_in,
    size_t index,
    size_t *written);

/**
 * Get the path from a PSBT keypath's serialized value.
 *
 * :param val: The serialized keypath value as stored in a keypath map.
 * :param val_len: Length of ``val`` in bytes.
 * :param child_path_out: Destination for the resulting path.
 * :param child_path_out_len: The number of items in ``child_path_out``.
 * :param written: Destination for the number of items written to ``child_path_out``.
 *
 * .. note:: If the path is longer than ``child_path_out_len``, `DOGECOIN_OK` is
 *|    returned and ``written`` contains the length required. It is valid
 *|    for a path to be zero-length.
 *
 * .. note:: This function should be used to read paths from serialized
 *|    keypath values to prevent endianness issues on big-endian hosts.
 */
LIBDOGECOIN_API int dogecoin_keypath_get_path(
    const unsigned char *val,
    size_t val_len,
    uint32_t *child_path_out,
    size_t child_path_out_len,
    size_t *written);

/**
 * Get the path from a PSBT keypath's serialized value.
 *
 * :param map_in: The map to return the item's path from.
 * :param index: The zero-based index of the item whose path to return.
 * :param child_path_out: Destination for the resulting path.
 * :param child_path_out_len: The number of items in ``child_path_out``.
 * :param written: Destination for the number of items written to ``child_path_out``.
 *
 * .. note:: See the notes for `dogecoin_keypath_get_path`.
 */
LIBDOGECOIN_API int dogecoin_map_keypath_get_item_path(
    const struct dogecoin_map *map_in,
    size_t index,
    uint32_t *child_path_out,
    size_t child_path_out_len,
    size_t *written);

/**
 * Verify a preimage map key and value pair.
 *
 * :param key: The preimage hash, prefixed by a hash type byte.
 * :param key_len: Length of ``key`` in bytes.
 * :param val: The preimage data hashed to produce ``key``.
 * :param val_len: Length of ``val`` in bytes.
 *
 * .. note:: Multiple preimage types are stored in the same map, prefixed by
 *|    a leading byte. The exact format of storage is implementation dependent
 *|    and may change in the future.
 */
LIBDOGECOIN_API int dogecoin_map_hash_preimage_verify(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *val,
    size_t val_len);

/**
 * Allocate and initialize a new preimage map.
 *
 * :param allocation_len: The number of items to allocate space for.
 * :param output: Destination for the new map.
 */
LIBDOGECOIN_API int dogecoin_map_preimage_init_alloc(
    size_t allocation_len,
    struct dogecoin_map **output);

/**
 * Add a ripemd160 preimage to a preimage map.
 *
 * :param map_in: The preimage map to add to.
 * :param value: The data to store.
 * :param value_len: Length of ``value`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_map_preimage_ripemd160_add(
    struct dogecoin_map *map_in,
    const unsigned char *value,
    size_t value_len);

/**
 * Add a sha256 preimage to a preimage map.
 *
 * :param map_in: The preimage map to add to.
 * :param value: The data to store.
 * :param value_len: Length of ``value`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_map_preimage_sha256_add(
    struct dogecoin_map *map_in,
    const unsigned char *value,
    size_t value_len);

/**
 * Add a hash160 preimage to a preimage map.
 *
 * :param map_in: The preimage map to add to.
 * :param value: The data to store.
 * :param value_len: Length of ``value`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_map_preimage_hash160_add(
    struct dogecoin_map *map_in,
    const unsigned char *value,
    size_t value_len);

/**
 * Add a sha256d preimage to a preimage map.
 *
 * :param map_in: The preimage map to add to.
 * :param value: The data to store.
 * :param value_len: Length of ``value`` in bytes.
 */
LIBDOGECOIN_API int dogecoin_map_preimage_sha256d_add(
    struct dogecoin_map *map_in,
    const unsigned char *value,
    size_t value_len);

#ifdef __cplusplus
}
#endif

#endif /* __LIBDOGECOIN_MAP_H__ */
