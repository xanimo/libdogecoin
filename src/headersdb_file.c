/*

 The MIT License (MIT)

 Copyright (c) 2017 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 
*/

#include <dogecoin/headersdb_file.h>
#include <dogecoin/block.h>
#include <dogecoin/crypto/common.h>
#include <dogecoin/serialize.h>
#include <dogecoin/utils.h>

#include <sys/stat.h>

#include <search.h>

/* The code below is creating a header magic number for the file. */
static const unsigned char file_hdr_magic[4] = {0xA8, 0xF0, 0x11, 0xC5}; /* header magic */
/* The code below is a simple way to store the version of the data structure. */
static const uint32_t current_version = 1;

/**
 * "Compare two block headers by their hashes."
 * 
 * The function takes two block headers as arguments, and returns 0 if the two headers are identical,
 * and -1 if the first header is less than the second header
 * 
 * @param l the first pointer
 * @param r The right-hand side of the comparison.
 * 
 * @return Nothing.
 */
int dogecoin_header_compare(const void *l, const void *r)
{
    const dogecoin_blockindex *lm = l;
    const dogecoin_blockindex *lr = r;

    uint8_t *hashA = (uint8_t *)lm->hash;
    uint8_t *hashB = (uint8_t *)lr->hash;

    /* byte per byte compare */
    for (unsigned int i = 0; i < sizeof(uint256); i++) {
        uint8_t iA = hashA[i];
        uint8_t iB = hashB[i];
        if (iA > iB)
            return -1;
        else if (iA < iB)
            return 1;
    }

    return 0;
}

/**
 * The function creates a new dogecoin_headers_db object and initializes it
 * 
 * @param chainparams The chainparams struct that contains the genesis block hash.
 * @param inmem_only If true, the database will be in-memory only. If false, it will be on disk.
 * 
 * @return Nothing.
 */
dogecoin_headers_db* dogecoin_headers_db_new(const dogecoin_chainparams* chainparams, dogecoin_bool inmem_only) {
    dogecoin_headers_db* db;
    db = dogecoin_calloc(1, sizeof(*db));

    db->read_write_file = !inmem_only;
    db->use_binary_tree = true;
    db->max_hdr_in_mem = 144;

    db->genesis.height = 0;
    db->genesis.prev = NULL;
    memcpy(db->genesis.hash, chainparams->genesisblockhash, DOGECOIN_HASH_LENGTH);
    db->chaintip = &db->genesis;
    db->chainbottom = &db->genesis;

    if (db->use_binary_tree) {
        db->tree_root = 0;
    }

    return db;
}

/**
 * It opens the file, reads the file into a tree, and then closes the file
 * 
 * @param db The database object.
 * 
 * @return Nothing
 */
void dogecoin_headers_db_free(dogecoin_headers_db* db) {

    /* Checking if the database is not null. */
    if (!db)
        return;

    /* Checking if the headers tree file is open. If it is, it closes it. */
    if (db->headers_tree_file)
    {
        fclose(db->headers_tree_file);
        db->headers_tree_file = NULL;
    }

    /* Freeing the memory allocated for the tree. */
    if (db->tree_root) {
        dogecoin_btree_tdestroy(db->tree_root, dogecoin_free);
        db->tree_root = NULL;
    }

    dogecoin_free(db);
}

/**
 * Loads the headers database from disk
 * 
 * @param db the headers database object
 * @param file_path The path to the headers database file. If NULL, the default path is used.
 * 
 * @return The return value is a boolean value that indicates whether the database was successfully
 * opened.
 */
dogecoin_bool dogecoin_headers_db_load(dogecoin_headers_db* db, const char *file_path) {

    if (!db->read_write_file) {
        /* stop at this point if we do inmem only */
        return 1;
    }

    char *file_path_local = (char *)file_path;
    cstring *path_ret = cstr_new_sz(1024);
    /* Checking if the file_path is empty. */
    if (!file_path)
    {
        /* The code below is a function that gets the default dogecoin data directory. */
        dogecoin_get_default_datadir(path_ret);
        char *filename = "/headers.db";
        /* Appending the filename to the path_ret buffer. */
        cstr_append_buf(path_ret, filename, strlen(filename));
        /* The code below is appending a null character to the end of the string. */
        cstr_append_c(path_ret, 0);
        /* The code below is creating a string that contains the path to the file. */
        file_path_local = path_ret->str;
    }

    struct stat buffer;
    dogecoin_bool create = true;
    /* Checking if the file exists. */
    if (stat(file_path_local, &buffer) == 0)
        create = false;

    /* The code below is opening the file in append mode. */
    db->headers_tree_file = fopen(file_path_local, create ? "a+b" : "r+b");
    /* The code below is freeing the memory allocated to the path_ret variable. */
    cstr_free(path_ret, true);
    /* Creating a new file called "test.txt" and writing the string "Hello World!" to it. */
    if (create) {
        // write file-header-magic
        fwrite(file_hdr_magic, 4, 1, db->headers_tree_file);
        uint32_t v = htole32(current_version);
        fwrite(&v, sizeof(v), 1, db->headers_tree_file); /* uint32_t, LE */
    } else {
        // check file-header-magic
        uint8_t buf[sizeof(file_hdr_magic)+sizeof(current_version)];
        /* Checking to see if the file is a valid database file. */
        if ((uint32_t)buffer.st_size < (uint32_t)(sizeof(file_hdr_magic)+sizeof(current_version)) ||
             fread(buf, sizeof(file_hdr_magic)+sizeof(current_version), 1, db->headers_tree_file) != 1 ||
             memcmp(buf, file_hdr_magic, sizeof(file_hdr_magic)))
        {
            fprintf(stderr, "Error reading database file\n");
            return false;
        }
        /* The code below is checking if the file version is greater than the current version. */
        if (le32toh(*(buf+sizeof(file_hdr_magic))) > current_version) {
            fprintf(stderr, "Unsupported file version\n");
            return false;
        }
    }
    dogecoin_bool firstblock = true;
    size_t connected_headers_count = 0;
    /* Checking if the headers tree file exists and if it does not, it will create it. */
    if (db->headers_tree_file && !create)
    {
        /* Reading the headers tree file line by line. */
        while (!feof(db->headers_tree_file))
        {
            /* The code below is creating a buffer to store the data that will be sent to the server. */
            uint8_t buf_all[32+4+80];
            /* It reads the header of the tree file into the buffer buf_all. */
            if (fread(buf_all, sizeof(buf_all), 1, db->headers_tree_file) == 1) {
                /* Creating a struct const_buffer that contains a pointer to the buffer buf_all and the
                size of the buffer. */
                struct const_buffer cbuf_all = {buf_all, sizeof(buf_all)};

                //load all

                /* deserialize the p2p header */
                uint256 hash;
                uint32_t height;
                /* Deserializing the hash from the buffer into a u256. */
                deser_u256(hash, &cbuf_all);
                /* Reading the height of the image from the buffer. */
                deser_u32(&height, &cbuf_all);
                dogecoin_bool connected;
                /* Checking if the first block is true. */
                if (firstblock)
                {
                    /* Creating a new dogecoin_blockindex object and initializing it to the default
                    values. */
                    dogecoin_blockindex *chainheader = dogecoin_calloc(1, sizeof(dogecoin_blockindex));
                    /* Setting the height of the chain header to the height of the block. */
                    chainheader->height = height;
                    /* Deserializing the block header. */
                    if (!dogecoin_block_header_deserialize(&chainheader->header, &cbuf_all)) {
                        /* The code below is freeing the memory allocated to the chainheader variable. */
                        dogecoin_free(chainheader);
                        fprintf(stderr, "Error: Invalid data found.\n");
                        return -1;
                    }
                    dogecoin_block_header_hash(&chainheader->header, (uint8_t *)&chainheader->hash);
                    chainheader->prev = NULL;
                    db->chaintip = chainheader;
                    firstblock = false;
                } else {
                    /* The code below is connecting to the dogecoin_headers_db_connect_hdr function. */
                    dogecoin_headers_db_connect_hdr(db, &cbuf_all, true, &connected);
                    if (!connected)
                    {
                        printf("Connecting header failed (at height: %d)\n", db->chaintip->height);
                    }
                    else {
                        connected_headers_count++;
                    }
                }
            }
        }
    }
    /* The code below is connecting the headers to the chain. */
    printf("Connected %ld headers, now at height: %d\n",  connected_headers_count, db->chaintip->height);
    return (db->headers_tree_file != NULL);
}

/**
 * The function takes a block index and writes it to the headers database
 * 
 * @param db the headers database
 * @param blockindex The block index to write to the database.
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_headers_db_write(dogecoin_headers_db* db, dogecoin_blockindex *blockindex) {
    /* Creating a new string of size 100. */
    cstring *rec = cstr_new_sz(100);
    /* Serializing the block index hash into the block record. */
    ser_u256(rec, blockindex->hash);
    /* Writing the block height to the file. */
    ser_u32(rec, blockindex->height);
    /* Serializing the block header into the buffer. */
    dogecoin_block_header_serialize(rec, &blockindex->header);
    /* Writing the record to the file. */
    size_t res = fwrite(rec->str, rec->len, 1, db->headers_tree_file);
    /* This is the code that writes the header tree to the database. */
    dogecoin_file_commit(db->headers_tree_file);
    /* Freeing the memory allocated for the record. */
    cstr_free(rec, true);
    return (res == 1);
}

/**
 * The function takes a pointer to a blockindex and checks if the block is in the blockchain. If it is,
 * it returns the pointer to the block. If it isn't, it returns a null pointer
 * 
 * @param db the database object
 * @param buf The buffer containing the block header.
 * @param load_process If true, the header will be loaded into the database. If false, it will only be
 * added to the tree.
 * @param connected A pointer to a boolean that will be set to true if the block was successfully
 * connected to the chain.
 * 
 * @return A pointer to the blockindex.
 */
dogecoin_blockindex * dogecoin_headers_db_connect_hdr(dogecoin_headers_db* db, struct const_buffer *buf, dogecoin_bool load_process, dogecoin_bool *connected) {
    *connected = false;

    /* Allocating memory for a dogecoin_blockindex struct and initializing it to all zeros. */
    dogecoin_blockindex *blockindex = dogecoin_calloc(1, sizeof(dogecoin_blockindex));
    /* Deserializing the block header from the buffer. */
    if (!dogecoin_block_header_deserialize(&blockindex->header, buf)) return NULL;

    /* calculate block hash */
    /* Hashing the block header. */
    dogecoin_block_header_hash(&blockindex->header, (uint8_t *)&blockindex->hash);

    dogecoin_blockindex *connect_at = NULL;
    dogecoin_blockindex *fork_from_block = NULL;
    /* try to connect it to the chain tip */
    /* The code below is checking if the previous block hash of the block we are about to add is the
    same as the hash of the current tip of the blockchain. */
    if (memcmp(blockindex->header.prev_block, db->chaintip->hash, DOGECOIN_HASH_LENGTH) == 0)
    {
        /* The code below is connecting the chain tip to the chain tip. */
        connect_at = db->chaintip;
    }
    else {
        // check if we know the prevblock
        /* Finding the previous block in the blockchain. */
        fork_from_block = dogecoin_headersdb_find(db, blockindex->header.prev_block);
        /* Creating a fork from the current block. */
        if (fork_from_block) {
            /* block found */
            printf("Block found on a fork...\n");
            /* The code below is creating a fork from the current block. */
            connect_at = fork_from_block;
        }
    }

    /* Checking if the user has specified a port to connect to. */
    if (connect_at != NULL) {
        /* TODO: check claimed PoW */
        /* Connecting the new block to the chain. */
        blockindex->prev = connect_at;
        /* Adding 1 to the height of the block that is being connected. */
        blockindex->height = connect_at->height+1;

        /* TODO: check if we should switch to the fork with most work (instead of height) */
        /* Checking if the block index height is greater than the current chain tip height. */
        if (blockindex->height > db->chaintip->height) {
            if (fork_from_block) {
                /* TODO: walk back to the fork point and call reorg callback */
                printf("Switch to the fork!\n");
            }
            /* Setting the chaintip to the blockindex. */
            db->chaintip = blockindex;
        }
        /* store in db */
        /* Checking if the process is loading a file and if the database is read/write. */
        if (!load_process && db->read_write_file)
        {
            /* Writing the block index to the database. */
            if (!dogecoin_headers_db_write(db, blockindex)) {
                fprintf(stderr, "Error writing blockheader to database\n");
            }
        }
        /* Checking if the database is using a binary tree. If it is, then it will set the value of the
        variable db->use_binary_tree to 1. */
        if (db->use_binary_tree) {
            /* Searching the tree for the blockindex. */
            tsearch(blockindex, &db->tree_root, dogecoin_header_compare);
        }

        /* Checking if the maximum number of headers in memory is set. */
        if (db->max_hdr_in_mem > 0) {
            // de-allocate no longer required headers
            // keep them only on-disk
            /* Checking if the database has a chaintip. If it does not, it will create a new chaintip. */
            dogecoin_blockindex *scan_tip = db->chaintip;
            /* Initializing the header array. */
            for(unsigned int i = 0; i<db->max_hdr_in_mem+1;i++)
            {
                /* Checking if the scan_tip is not the first scan_tip in the linked list. */
                if (scan_tip->prev) {
                    /* Moving the scan_tip pointer to the previous node. */
                    scan_tip = scan_tip->prev;
                } else {
                    break;
                }

                /* Checking if the scan tip is the genesis block and if it is, it is checking if the
                maximum number of headers in memory has been reached. If it has, it is checking if
                the scan tip is not the genesis block. If it is not the genesis block, it is setting
                the scan tip to the genesis block. */
                if (scan_tip && i == db->max_hdr_in_mem && scan_tip != &db->genesis) {
                    if (scan_tip->prev && scan_tip->prev != &db->genesis) {
                        /* Deleting the scan_tip from the tree. */
                        tdelete(scan_tip->prev, &db->tree_root, dogecoin_header_compare);
                        /* Freeing the memory of the previous block. */
                        dogecoin_free(scan_tip->prev);
                        /* Setting the previous pointer of the scan_tip to NULL. */
                        scan_tip->prev = NULL;
                        /* Setting the chainbottom of the database to the scan_tip. */
                        db->chainbottom = scan_tip;
                    }
                }
            }
        }
        *connected = true;
    }
    else {
        //TODO, add to orphans
        char hex[65] = {0};
        /* The code below is converting the block index hash to a hex string. */
        utils_bin_to_hex(blockindex->hash, DOGECOIN_HASH_LENGTH, hex);
    }

    return blockindex;
}

/**
 * The function iterates through the chain tip and adds the hash of each block to the blocklocators
 * vector
 * 
 * @param db the database object
 * @param blocklocators a vector of block hashes
 */
void dogecoin_headers_db_fill_block_locator(dogecoin_headers_db* db, vector *blocklocators)
{
    /* Checking if the database has a chaintip. If it does not, it will create a new chaintip. */
    dogecoin_blockindex *scan_tip = db->chaintip;
    /* Checking if the scan tip is above the scan surface. */
    if (scan_tip->height > 0)
    {
        for(int i = 0; i<10;i++)
        {
            //TODO: try to share memory and avoid heap allocation
            /* Allocating memory for a uint256 and then initializing it to 0. */
            uint256 *hash = dogecoin_calloc(1, sizeof(uint256));
            /* Copying the hash of the tip of the chain into the hash variable. */
            memcpy(hash, scan_tip->hash, sizeof(uint256));

            /* The code below is adding the hash of the block to the blocklocators vector. */
            vector_add(blocklocators, (void *)hash);
            /* Checking if the scan_tip has a previous node. */
            if (scan_tip->prev)
                /* Moving the scan_tip pointer to the previous node. */
                scan_tip = scan_tip->prev;
            else
                break;
        }
    }
}

/**
 * The function takes a hash and returns the blockindex with that hash
 * 
 * @param db The headers database.
 * @param hash The hash of the block header to find.
 * 
 * @return A pointer to the blockindex.
 */
dogecoin_blockindex * dogecoin_headersdb_find(dogecoin_headers_db* db, uint256 hash) {
    /* Checking if the database is using a binary tree. */
    if (db->use_binary_tree)
    {
        /* Allocating memory for a dogecoin_blockindex struct and initializing it to zero. */
        dogecoin_blockindex *blockindex = dogecoin_calloc(1, sizeof(dogecoin_blockindex));
        /* Copying the hash of the block into the block index. */
        memcpy(blockindex->hash, hash, sizeof(uint256));
        /* Searching the tree for the blockindex with the given hash. */
        dogecoin_blockindex *blockindex_f = tfind(blockindex, &db->tree_root, dogecoin_header_compare); /* read */
        if (blockindex_f) {
            /* Checking if the blockindex_f is not null. If it is not null, it will set the
            blockindex_f to the next blockindex. */
            blockindex_f = *(dogecoin_blockindex **)blockindex_f;
        }
        /* The code below is freeing the memory allocated to the blockindex variable. */
        dogecoin_free(blockindex);
        return blockindex_f;
    }
    return NULL;
}

/**
 * Get the block index of the current tip of the main chain
 * 
 * @param db The headers database.
 * 
 * @return The current tip of the blockchain.
 */
dogecoin_blockindex * dogecoin_headersdb_getchaintip(dogecoin_headers_db* db) {
    /* The code below is returning the chain tip of the database. */
    return db->chaintip;
}

/**
 * If the chaintip is not null, then set the chaintip to the previous block and return true. Otherwise
 * return false
 * 
 * @param db The headers database.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_headersdb_disconnect_tip(dogecoin_headers_db* db) {
    /* Checking if the chain tip has a previous block. */
    if (db->chaintip->prev)
    {
        /* Creating a new dogecoin_blockindex object and setting it to the current tip of the
        blockchain. */
        dogecoin_blockindex *oldtip = db->chaintip;
        /* The code below is removing the last node from the list. */
        db->chaintip = db->chaintip->prev;
        /* disconnect/remove the chaintip */
        /* Deleting the old tip from the tree. */
        tdelete(oldtip, &db->tree_root, dogecoin_header_compare);
        /* Freeing the memory of the old tip. */
        dogecoin_free(oldtip);
        return true;
    }
    return false;
}

/**
 * "Check if the headers database has a checkpoint start."
 * 
 * The function returns a bool value
 * 
 * @param db The headers database.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_headersdb_has_checkpoint_start(dogecoin_headers_db* db) {
    /* The code below is checking to see if the chainbottom is not equal to zero. */
    return (db->chainbottom->height != 0);
}

/**
 * Set the checkpoint block to the given hash and height
 * 
 * @param db The headers database.
 * @param hash The hash of the block that is the checkpoint.
 * @param height The height of the block that this is a checkpoint for.
 */
void dogecoin_headersdb_set_checkpoint_start(dogecoin_headers_db* db, uint256 hash, uint32_t height) {
    /* Creating a new blockindex object and setting it to the chainbottom. */
    db->chainbottom = dogecoin_calloc(1, sizeof(dogecoin_blockindex));
    /* Setting the height of the bottom chain to the height of the top chain. */
    db->chainbottom->height = height;
    /* Copying the hash of the previous block into the hash of the current block. */
    memcpy(db->chainbottom->hash, hash, sizeof(uint256));
    /* Setting the chain tip to the chain bottom. */
    db->chaintip = db->chainbottom;
}
