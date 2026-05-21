# Using Libdogecoin Tools

## Overview

If you are looking to just explore the functionality of Libdogecoin without building a complicated project yourself, look no further than the CLI tools provided in this repo. The first tool, `such`, is an interactive CLI application that allows you to perform all Essential address and transaction operations with prompts to guide you through the process. The second tool, `sendtx`, handles the process of broadcasting a transaction built using Libdogecoin to eventually push it onto the blockchain. The third tool, `spvnode`, run a Simple Payment Verification (SPV) node for the Dogecoin blockchain. It enables users to interact with the Dogecoin network, verify transactions and stay in sync with the blockchain.

This document goes over the usage of these tools along with examples of how to use them.

## The `such` Tool
As stated above, the `such` tool can be used to perform all Libdogecoin address and transaction functions, and even more. It can generate different types of public and private keys, derive and convert keys, and fully build and sign transactions.

### Usage
The `such` tool can be used by simply running the command `./such` in the top level of the Libdogecoin directory, always followed by a `-c` flag that denotes the desired `such` command to run. The options for this command are below:
- generate_private_key
- generate_public_key
- p2pkh
- bip32_extended_master_key
- derive_child_keys
- generate_mnemonic
- list_encryption_keys_in_tpm
- decrypt_master_key
- decrypt_mnemonic
- seed_to_master_key
- mnemonic_to_key
- mnemonic_to_addresses
- print_keys
- sign
- comp2der
- bip32maintotest
- signmessage
- verify_message
- transaction
- set_scriptsig
- pqc_chunk_hex
- tx_sighash32 (requires --enable-liboqs)
- pqc_carrier_redeemscript (requires --enable-liboqs)
- pqc_carrier_scriptpubkey (requires --enable-liboqs)
- pqc_carrier_mkpart (requires --enable-liboqs)
- pqc_carrier_parsepart (requires --enable-liboqs)
- falcon_keygen (requires --enable-liboqs)
- falcon_sign (requires --enable-liboqs)
- falcon_verify (requires --enable-liboqs)
- falcon_commit (requires --enable-liboqs)
- falcon_add_commit_tx (requires --enable-liboqs)
- falcon_add_commit_and_carrier_tx (requires --enable-liboqs)
- dilithium2_keygen (requires --enable-liboqs)
- dilithium2_sign (requires --enable-liboqs)
- dilithium2_verify (requires --enable-liboqs)
- dilithium2_commit (requires --enable-liboqs)
- dilithium2_add_commit_tx (requires --enable-liboqs)
- dilithium2_add_commit_and_carrier_tx (requires --enable-liboqs)
- raccoong_keygen (requires --enable-raccoon-g)
- raccoong_sign (requires --enable-raccoon-g)
- raccoong_verify (requires --enable-raccoon-g)
- raccoong_commit (requires --enable-raccoon-g)
- raccoong_hd_derive (requires --enable-raccoon-g)
- raccoong_hd_derive_pub (requires --enable-raccoon-g)
- raccoong_add_commit_tx (requires --enable-raccoon-g)
- raccoong_add_commit_and_carrier_tx (requires --enable-raccoon-g)

So an example run of `such` could be something like this:
```
./such -c generate_private_key
```
Most of these commands require a flag following them to denote things like existing keys, transaction hex strings, and more:

| Flag | Name | Required Arg? | Usage |
| -    | -    | -             |-      |
| -p, --privkey  | private_key         | yes | generate_public_key -p <private_key> |
| -k, --pubkey  | public_key          | yes | p2pkh -k <public_key> |
| -m, --derived_path | derived_path        | yes | derive_child_key -p <extended_private_key> -m <derived_path> |
| -e, --entropy  | hex_entropy | yes | generate_mnemonic -e <hex_entropy> |
| -z, --entropy_size  | entropy_size | yes | generate_mnemonic -z <entropy_size> |
| -n, --mnemonic  | seed_phrase | yes | mnemonic_to_key or mnemonic_to_addresses -n <seed_phrase> |
| -a, --pass_phrase  | pass_phrase | no | mnemonic_to_key or mnemonic_to_addresses -n <seed_phrase> -a |
| -o, --account_int  | account_int | yes | mnemonic_to_key or mnemonic_to_addresses -n <seed_phrase> -o <account_int> |
| -g, --change_level  | change_level | yes | mnemonic_to_key or mnemonic_to_addresses -n <seed_phrase> -g <change_level> |
| -i, --address_index  | address_index | yes | mnemonic_to_key or mnemonic_to_addresses -n <seed_phrase> -i <address_index> |
| -y, --encrypted_file | file_num | yes | generate_mnemonic, bip32_extended_master_key, decrypt_master_key, decrypt_mnemonic, seed_to_master_key, mnemonic_to_key or mnemonic_to_addresses -y <file_num>
| -w, --overwrite | overwrite | no | generate_mnemonic or bip32_extended_master_key -w |
| -b, --silent | silent | no | generate_mnemonic or bip32_extended_master_key -b |
| -j, --use_tpm | use_tpm | no | generate_mnemonic, bip32_extended_master_key, decrypt_master_key, decrypt_mnemonic, seed_to_master_key, mnemonic_to_key or mnemonic_to_addresses -j |
| -t, --testnet  | designate_testnet   | no  | generate_private_key -t |
| -s  | script_hex          | yes | comp2der -s <compact_signature> |
| -x  | transaction_hex     | yes | sign -x <transaction_hex> -s <pubkey_script> -i <index_of_utxo_to_sign> -h <sig_hash_type> |
| -i  | input_index         | yes | see above |
| -h  | sighash_type        | yes | see above |

Below is a list of all the commands and the flags that they require. As a reminder, any command that includes the `-t` flag will set the default chain used in internal calculations to _testnet_ rather than _mainnet_. Also included are descriptions of what each function does.

| Command | Required flags | Optional flags | Description |
| -                         | -                      | -    | - |
| generate_private_key      | None                   | -t   | Generates a private key from a secp256k1 context for either mainnet or testnet. |
| generate_public_key       | -p                     | -t   | Generates a public key derived from the private key specified. Include the testnet flag if it was generated from testnet. |
| p2pkh                     | -k                     | -t   | Generates a p2pkh address derived from the public key specified. Include the testnet flag if it was generated from testnet. |
| bip32_extended_master_key | None                   | -t   | Generate an extended master private key from a secp256k1 context for either mainnet or testnet. |
| bip32maintotest           | -p                     | None | Convert a mainnet private key into an equivalent testnet key. |
| derive_child_keys         | -p, -m                 | -t   | Generates a child key derived from the specified public or private key using the specified derivation path.
| generate_mnemonic         | None                   | -e, -y, -w, -b | Generates a 24-word english seed phrase randomly or from optional hex entropy. |
| list_encryption_keys_in_tpm | None                 | None | List the encryption keys in the TPM. |
| decrypt_master_key | -y   | -j | Decrypt the master key with the TPM or SW. |
| decrypt_mnemonic | -y     | -j | Decrypt the mnemonic with the TPM or SW. |
| seed_to_master_key | -y   | -j, -t | Generates an extended master private key from a seed for either mainnet or testnet. |
| mnemonic_to_key | -n      | -a, -y, -o, g, -i, -t | Generates a private key from a seed phrase with a default path or specified account, change level and index for either mainnet or testnet. |
| mnemonic_to_addresses     | -n      | -a, -y, -o, g, -i, -t   | Generates an address from a seed phrase with a default path or specified account, change level and index for either mainnet or testnet. |
| print_keys                | -p                     | -t   | Print all keys associated with the provided private key.
| sign                      | -x, -s, -i, -h, -p     | -t   | See the definition of sign_raw_transaction in the Transaction API.
| comp2der                  | -s                     | None | Convert a compact signature to a DER signature.
| signmessage               | -x, -p                 | None | Sign a message and output a base64 encoded signature and address.
| verify_message             | -x, -s, -k             | None | Verify a message by public key recovery of base64 decoded signature and comparison of addresses.
| transaction               | None                   | None | Start the interactive transaction app. [Usage instructions below.]() |
| set_scriptsig             | -x, -i, -s            | None | Set a custom scriptSig on a transaction input. |
| pqc_chunk_hex             | -x                     | -h   | Splits a hex payload into ≤max_chunk_bytes chunks (default 520). |

Lastly, to display the version of `such`, simply run the following command, which overrides any previous ones specified:
```
./such -v
```

### Examples
Below are some examples on how to use the `such` tool in practice.

##### Generate a new private key WIF and hex encoded:

    ./such -c generate_private_key
    > privatekey WIF: QSPDnjzvrSPAeiM7N2jCkzv2dqsi7fxoHipgpPfz2zdE3ZpYp74j
    > privatekey HEX: 7073fa30281cf89195dca333134368d539e7abad712abb532c9eaf5f3666d9d1

##### Generate the public key, p2pkh, and p2sh-p2pkh address from a WIF encoded private key

    ./such -c generate_public_key -p QSPDnjzvrSPAeiM7N2jCkzv2dqsi7fxoHipgpPfz2zdE3ZpYp74j
    > pubkey: 02cf2c99c2db4b3d72d4289aa23bdaf5f3ccf4867ec8e5f8223ea716a7a3de10bc
    > p2pkh address: D62RKK6AGkzX6fM8RzoVM8fjPx2nzrdvKU

##### Generate the P2PKH address from a hex encoded compact public key

    ./such -c generate_public_key -pubkey 02cf2c99c2db4b3d72d4289aa23bdaf5f3ccf4867ec8e5f8223ea716a7a3de10bc
    > p2pkh address: D62RKK6AGkzX6fM8RzoVM8fjPx2nzrdvKU

##### Generate new BIP32 master key

    ./such -c bip32_extended_master_key
    > masterkey: dgpv51eADS3spNJh9qLpW8S7B7uZmusTpNE85NgXsYD7eGuVhebMDfEsj6fNR6DHgpSBCmYdAvw9YRSqRWnFxtYn1bM8AdNipwdi9dDXFCY8vkY


##### Print HD node

    ./such -c print_keys -privkey dgpv51eADS3spNJh9qLpW8S7B7uZmusTpNE85NgXsYD7eGuVhebMDfEsj6fNR6DHgpSBCmYdAvw9YRSqRWnFxtYn1bM8AdNipwdi9dDXFCY8vkY
    > ext key:             dgpv51eADS3spNJh9qLpW8S7B7uZmusTpNE85NgXsYD7eGuVhebMDfEsj6fNR6DHgpSBCmYdAvw9YRSqRWnFxtYn1bM8AdNipwdi9dDXFCY8vkY
    > extended pubkey:     dgub8kXBZ7ymNWy2SgzyYN45HyTAEUF6eVFqMyTk2ec6SPxWFhi3dRneNQ51zJadLERvA1ns9uvMGKM9wYKTSnCP9QrSPJMCKjdfSv4qmT3PkP2
    > pubkey hex:          025368ca428b4c4e0c48631c5f8510d704858a52c7264d4ba74f34b2bcee374220
    > privatekey WIF:      QTtXPXYWc4G6WuA6qNRYeQ3TAdsBUUqrLwN1eWVFEvfHdd8M1ed5
    > depth:               0
    > child index:         0
    > p2pkh address:       D79Q3spkucaM2DvLxUZjgV1X4cQcWDLuyt

##### Derive child key (second child key at level 1 in this case)

    ./such -c derive_child_keys -m m/1h -privkey dgpv51eADS3spNJh9qLpW8S7B7uZmusTpNE85NgXsYD7eGuVhebMDfEsj6fNR6DHgpSBCmYdAvw9YRSqRWnFxtYn1bM8AdNipwdi9dDXFCY8vkY
    > ext key:             dgpv53gfwGVYiKVgf3hybqGjXuxrW2s2iCArhBURxAWaFszfqfP6wc23KFVyCuGj4fGzAX6oC8QmvhvkWz18v4VcdhzYCxoTR3XQizrVtjMwQHS
    > extended pubkey:     dgub8nZhGxRSGUA1wuN8e4themWSxbEfYKCZynFe7GuZ413gPiVoMNZoxYucn8DQ5doeqt1cmZnxZ4Ms9SdsraiSbUkZSYbx1GzpGbrAqmFdSSL
    > pubkey hex:          023973b755fdaf5b2b7b20ac134c936ec7882b1ce0a3a75857fc490c12cdf4fb4f
    > privatekey WIF:      QQUwLsFpWWXsHFLCxjvBMn8Qd4Pgqji5QUXz6zN8vkiKMPvv7mpZ
    > depth:               1
    > child index:         -2147483647
    > p2pkh address:       DFqonEEA56VE8zEGvhXNgjiPT3PaPFNQQu

##### Derive public child key (second child key at level 2 in this case, non-hardened)

    ./such -c derive_child_keys -m m/1 -p dgub8sdBNNzYwKo1KKQcQoJXMDwEg3fgX52aY2aSuSGMXepn71kMtZoN7BVwWp7JT582EDT8djTpCMx7Nd62nJ8u8xNmszEXrmsHWf6XQccjiLg
    > ext key:             dgub8q9VuPpS4NijK4e7Cc7WaKGD6QHjUB3YkJi83imYVvBRGjrKwPcNFjNcmNt2UnEuhFmKhcmo8aRQABUhq55H3ackUBGj3nJDTMpcP6ALoiN
    > extended pubkey:     dgub8q9VuPpS4NijK4e7Cc7WaKGD6QHjUB3YkJi83imYVvBRGjrKwPcNFjNcmNt2UnEuhFmKhcmo8aRQABUhq55H3ackUBGj3nJDTMpcP6ALoiN
    > pubkey hex:          02cbfea5f5cf7d28b9111e92f05356a39a64f19247e539b428ef91e70a6900ae71
    > depth:               2
    > child index:         1
    > p2pkh address:       D7M52mS3ZTrPXgRmfjpV5pPSG2E2TsfZAi

#### Generate a random BIP39 seed phrase
#### See "Seed phrases" in address.md, for additional guidance

    ./such -c generate_mnemonic
    > they nuclear observe moral twenty gym hedgehog damage reveal syrup negative beach best silk alone feel vapor deposit belt host purity run clever deer

#### Generate a HD master key from the seed phrase for a given account (2), change level (1, internal) and index (0) for testnet

    ./such -c mnemonic_to_key -n "they nuclear observe moral twenty gym hedgehog damage reveal syrup negative beach best silk alone feel vapor deposit belt host purity run clever deer" -o 2 -g 1 -i 0 -t
    > keypath: m/44'/1'/2'/1/0
    > private key (wif): cniAjMkD7HpzQKw67ByNsyzqMF8MEJo2y4viH2WEZRXoKHNih1sH

#### Generate an HD address from the seed phrase for a given account (2), change level (1, internal) and index (0) for testnet

    ./such -c mnemonic_to_addresses -n "they nuclear observe moral twenty gym hedgehog damage reveal syrup negative beach best silk alone feel vapor deposit belt host purity run clever deer" -o 2 -g 1 -i 0 -t
    > Address: nW7ndt4HZh8XwLYN6v6N2S4mZCbpZPuFxh

#### Generate a BIP39 seed phrase from hex entropy

    ./such -c generate_mnemonic -e "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    > zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote

#### Geneate an HD address from the seed phrase and default path (m/44'/3'/0'/0/0) for mainnet

    ./such -c mnemonic_to_addresses -n "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
    > Address: DTdKu8YgcxoXyjFCDtCeKimaZzsK27rcwT

#### Sign an arbitrary message

    ./such -c signmessage -x bleh -p QWCcckTzUBiY1g3GFixihAscwHAKXeXY76v7Gcxhp3HUEAcBv33i
    message: bleh
    content: ICrbftD0KamyaB68IoXbeke3w4CpcIvv+Q4pncBNpMk8fF5+xsR9H9gqmfM0JrjlfzZZA3E8AJ0Nug1KWeoVw3g=
    address: D8mQ2sKYpLbFCQLhGeHCPBmkLJRi6kRoSg

#### Verify an arbitrary message

    ./such -c verifymessage -x bleh -s ICrbftD0KamyaB68IoXbeke3w4CpcIvv+Q4pncBNpMk8fF5+xsR9H9gqmfM0JrjlfzZZA3E8AJ0Nug1KWeoVw3g= -k D8mQ2sKYpLbFCQLhGeHCPBmkLJRi6kRoSg
    Message is verified!

## Encrypted Mnemonics, Key and Seed Backups

The `such` tool provides functionality to securely manage your encrypted mnemonics, key and seed backups. With the ability to generate mnemonics and encrypt them for safe storage, and to decrypt them when needed, managing your cryptographic assets is made easier. To use encrypted files with `spvnode`, you must first use the `such` tool to generate and encrypt your mnemonic or master key. You can then use the `spvnode` tool to import the encrypted file and use it to connect to the network.

### Generating and Encrypting Mnemonics

To generate a new mnemonic, which is a 24-word seed phrase, you can use the following command:

    ./such -c generate_mnemonic

The `z` flag can be used to specify the size of the entropy used to generate the mnemonic. The default size is 256 bits, which generates a 24-word mnemonic. For example, to generate a mnemonic with 128 bits of entropy, you can use the following command:

    ./such -c generate_mnemonic -z 128

You can also use the `e` flag to provide your own hex-encoded entropy to generate the mnemonic. For example:

    ./such -c generate_mnemonic -e FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

This will output a new mnemonic that you can use to generate keys and addresses. If you want to encrypt this mnemonic to keep it safe, you can use the following command:

    ./such -c generate_mnemonic -y <file_num>

The `-y` flag is used to specify the file number to use for encryption. This number is used to identify the encrypted file when you need to decrypt it. You can also use the `-w` flag to overwrite an existing file with the same number. If you want to encrypt the mnemonic using a TPM (Trusted Platform Module), you can use the `-j` flag as shown:

    ./such -c generate_mnemonic -y <file_num> -j

Replace `<file_num>` with the appropriate file number you want to use for encryption (e.g. 0, 1, 2, etc.). `999` is reserved for testing purposes.

Encrypting a mnemonic will output a file with the encrypted mnemonic. You can use the `-b` flag to suppress the mnemonic output and only output the encrypted file. This is useful if you want to encrypt a mnemonic and save it to a file without displaying the mnemonic on the screen. For example:

    ./such -c generate_mnemonic -y <file_num> -b

All encryted files are saved in the store directory. On Linux, this is `.store` in the libdogecoin directory. On Windows, this is the `store` directory in the libdogecoin directory.

### Decrypting Mnemonics

When you need to access your encrypted mnemonic, you can decrypt it using the `decrypt_mnemonic` command. If the mnemonic was encrypted using TPM (Trusted Platform Module), you can use the `-j` flag as shown:

    ./such -c decrypt_mnemonic -y <file_num> -j

Replace `<file_num>` with the appropriate file number you used during encryption.

### Handling Key Backups

You can also encrypt and decrypt your master key using similar commands. To encrypt a master key, you might first generate it and then encrypt as follows:

    ./such -c bip32_extended_master_key -y <file_num> -j

And to decrypt it back when required:

    ./such -c decrypt_master_key -y <file_num> -j

Always ensure to replace `<file_num>` with the actual number of the encrypted file.

### Handling Seed Backups

You can also decrypt your seed backups using the `seed_to_master_key` command. This command will decrypt the seed and generate a master key from it. If the seed was encrypted using TPM (Trusted Platform Module), you can use the `-j` flag as shown:

    ./such -c seed_to_master_key -y <file_num> -j

### Overwriting Encrypted Files

If you want to overwrite an existing encrypted file, you can use the `-w` flag as shown:

    ./such -c generate_mnemonic -y <file_num> -w

This will overwrite the existing file with the same number. You can also use the `-w` flag with the `bip32_extended_master_key` command to overwrite an existing encrypted master key.

### Best Practices

- **Backup**: Always backup your encrypted files in multiple secure locations. Adhering to the "rule of three" is advised, meaning you should have three copies of your data: the original, a primary backup, and a secondary backup, ideally kept in different locations to mitigate the risk of data loss due to environmental factors.
- **File Numbers**: Encrypting files with the same file number will overwrite the previous file with the same number of that type. This is useful for overwriting old backups with new ones, but can be dangerous if you accidentally overwrite a file you need. Always keep track of your file numbers and what they are used for.
- **Security**: Use a TPM where available for added security during encryption and decryption processes.  Encryption keys are stored in the TPM and never leave the TPM.  The TPM is a hardware device that is designed to be tamper resistant.  If you do not have a TPM, you can use software encryption and decryption, but this is less secure than using a TPM.
- **Overwrites**: Overwriting encrypted files is irreversible. Files and backups encrypted with TPM cannot be decrypted once overwritten.  Files and backups encrypted with software can be decrypted with software, but the original file will be lost.

### Important Notes (General)

 - **If you lose your encrypted files, you will not be able to decrypt your mnemonics or master keys.**

 - **If you lose your mnemonic or master key, you will not be able to recover your coins.**

 - **Overwriting encrypted files is irreversible.**

### Important Notes (TPM-specific)

 - **If you lose your TPM, you will not be able to decrypt your mnemonics or master keys.**

 - **TPM encrypted files cannot be decrypted with software.**

These commands and flags are part of the `such` CLI tool's functionality, enabling a robust management system for your encrypted data within the Libdogecoin ecosystem.

### Interactive Transaction Building with `such`

When you start the interactive `such` transaction tool with `./such -c transaction`, you will be faced with a menu of options. To choose one of these options to execute, simply type the number of that command and hit enter.

| Command | Description |
| -       | -           |
| add transaction           | Start building a new transaction. |
| edit transaction by id    | Make changes to a transaction that has already been started. |
| find transaction          | Print out the hex of a transaction that has already been started. |
| sign transaction          | Sign the inputs of a finalized transaction. |
| delete transaction        | Remove an existing transaction from memory. |
| delete all transactions   | Remove all existing transactions from memory. |
| print transactions        | Start building a new transaction. |
| import raw transaction    | Saves the entered transaction hex as a transaction object in memory. |
| broadcast transaction     | Performs the same operation as [`./sendtx`] (#the-sendtx-tool) (`sendtx` recommended) |
| change network            | Specify the network for building transactions. |
| quit                      | Exit the tool. |

Once you choose a command, there will be on-screen prompts to guide your next actions. All of these commands internally call the functions that make up Libdogecoin, so for more information on what happens when these commands are run, please refer to the [Libdogecoin Essential Transaction API](doc/../transaction.md).



## The `sendtx` Tool

Now that you've built a sendable transaction with Libdogecoin, `sendtx` is here to broadcast that transaction so that it can be published on the blockchain. You can broadcast to peers retrieved from a DNS seed or specify with IP/port. The application will try to connect to a default maximum of 10 peers, send the transaction to two of them, and listen on the remaining ones if the transaction has been relayed back. Alongside Libdogecoin, `sendtx` gives you the capability to publish your own transactions directly to the blockchain without using external services.

### Usage

Similar to `such`, `sendtx` is simple to run and is invoked by simply running the command `./sendtx` in the top level of the Libdogecoin directory, which is then simply followed by the transaction hex to broadcast rather than a command like in `such`. There are still several flags that may be helpful

| Flag | Name | Required Arg? | Usage |
| -   | -                   | -   |-  |
| -t, --testnet  | designate_testnet   | no  | ./sendtx -t <tx_hex_for_testnet> |
| -r, --regtest  | designate_regtest   | no  | ./sendtx -r <tx_hex_for_regtest> |
| -d, --debug    | designate_debug     | no  | ./sendtx -d <tx_hex> |
| -s, --timeout  | timeout_threshold   | yes | ./sendtx -s 10 <tx_hex> |
| -i, --ips      | ip_addresses        | yes | ./sendtx -i 127.0.0.1:22556,192.168.0.1:22556 <tx_hex>|
| -m, --maxnodes | max_connected_nodes | yes | ./sendtx -m 6 <tx_hex> |

Lastly, to display only the version of `sendtx`, simply run the following command:
```
./sendtx -v
```

### Examples
Below are some examples on how to use the `sendtx` tool in practice.

##### Send a raw transaction to random peers on mainnet

    ./sendtx <tx_hex>

##### Send a raw transaction to random peers on testnet and show debug information

    ./sendtx -d -t <tx_hex>

##### Send a raw transaction to specific peers on mainnet and show debug information using a timeout of 5s

    ./sendtx -d -s 5 -i 192.168.1.110:22556,127.0.0.1:22556 <tx_hex>

##### Send a raw transaction to at most 5 random peers on mainnet

    ./sendtx -m 5 <tx_hex>


## The `spvnode` Tool

`spvnode` is a command-line tool that operates a Simple Payment Verification (SPV) node for the Dogecoin blockchain. It enables users to interact with the Dogecoin network, verify transactions, and stay in sync with the blockchain.

### Operation Modes

`spvnode` supports two operational modes:

1. **Header-Only Mode**: This mode is for quickly catching up with the blockchain by downloading only the block headers. This mode is typically used for initial sync, and then the node can switch to full block mode for verifying transactions.

2. **Full Block Mode**: After catching up with the blockchain headers, `spvnode` can switch to this mode to download full blocks for detailed transaction history scanning. This is essential for verifying transactions related to the user's wallet addresses.

### Usage

To use `spvnode`, execute it from the top level of the Libdogecoin directory. Start the tool by running `./spvnode` followed by the `scan` command. There are several flags that can be used to customize the behavior of `spvnode`:

Each flag is accompanied by a description and usage example. To view the version of `spvnode`, simply run:

    ./spvnode -v

Run `spvnode` in header-only mode for a fast catch-up:

    ./spvnode scan

To activate full block validation mode for comprehensive address scanning, include the -b flag:

    ./spvnode -b scan

To utilize checkpoints for faster initial sync, apply the -p flag:

    ./spvnode -p scan

To enable BIP37 filtered block mode (filterload + merkleblock history scan), apply the -g flag:

    ./spvnode -g scan

To choose a checkpoint start manually (all available checkpoints shown), apply the -q flag:

    ./spvnode -q scan

| Flag | Name | Required Arg? | Usage |
|------|------|---------------|-------|
| `-t`, `--testnet` | Testnet Mode | No | Activate testnet: `./spvnode -t scan` |
| `-r`, `--regtest` | Regtest Mode | No | Activate regtest network: `./spvnode -r scan` |
| `-i`, `--ips` | Initial Peers | Yes | Specify initial peers: `./spvnode -i 127.0.0.1:22556 scan` |
| `-d`, `--debug` | Debug Mode | No | Enable debug output: `./spvnode -d scan` |
| `-m`, `--maxnodes` | Max Peers | No | Set max peers: `./spvnode -m 8 scan` |
| `-a`, `--address` | Address | Yes | Use address: `./spvnode -a "your address here" scan` |
| `-n`, `--mnemonic` | Mnemonic Seed | Yes | Use BIP39 mnemonic: `./spvnode -n "your mnemonic here" scan` |
| `-s`, `--pass_phrase` | Passphrase | No | Passphrase for BIP39 seed: `./spvnode -s scan` |
| `-f`, `--dbfile` | Database File | No | Headers DB file/mem-only (0): `./spvnode -f 0 scan` |
| `-c`, `--continuous` | Continuous Mode | No | Run continuously: `./spvnode -c scan` |
| `-b`, `--full_sync` | Full Sync | No | Perform a full sync: `./spvnode -b scan` |
| `-p`, `--checkpoint` | Checkpoint | No | Enable checkpoint sync: `./spvnode -p scan` |
| `-w`, `--wallet_file` | Wallet File | Yes | Specify wallet file: `./spvnode -w "./wallet.db" scan` |
| `-h`, `--headers_file` | Headers File | Yes | Specify headers DB file: `./spvnode -h "./headers.db" scan` |
| `-l`, `--no_prompt` | No Prompt | No | Load wallet and headers without prompt: `./spvnode -l scan` |
| `-y`, `--encrypted_file` | Encrypted File | Yes | Use encrypted file: `./spvnode -y 0 scan` |
| `-j`, `--use_tpm` | Use TPM | No | Utilize TPM for decryption: `./spvnode -j scan` |
| `-k`, `--master_key` | Master Key | No | Use master key decryption: `./spvnode -k scan` |
| `-z`, `--daemon` | Daemon Mode | No | Run as a daemon: `./spvnode -z scan` |
| `-u`, `--http_server` | Enable HTTP | No | Enabled HTTP: `./spvnode -u 127.0.0.1:8080 scan` |
| `-x`, `--smpv` | Enable SMPV | No | Enabled SMPV: `./spvnode -x scan` |
| `-g`, `--filtered_blocks` | Filtered Blocks | No | Enable BIP37 filtered blocks: `./spvnode -g scan` |
| `-q`, `--select_checkpoint` | Select Checkpoint | No | Prompt for checkpoint start (defaults to latest when used with `-l`): `./spvnode -q scan` |

### Commands

The primary command for `spvnode` is `scan`, which syncs the blockchain headers:

#### `scan`
Connects to the Dogecoin network and synchronizes the blockchain headers to the local database.

### Callback Functions

The tool provides several callbacks for custom integration:

- `spv_header_message_processed`: Triggered when a header is processed.
- `spv_sync_completed`: Invoked upon completion of the sync process.

### Best Practices and Notes
When not specifying -w, spvnode will default to using main_wallet.db. To prevent unintended interactions with main_wallet.db, it's important to be consistent with the use of flags. The best practice is to always use -w and specify a distinct wallet file, especially when using new mnemonics or keys.

When using -n with a mnemonic, instead of main_wallet.db, spvnode will generate main_mnemonic_wallet.db.

## Examples

#### Sync up to the chain tip and stores all headers in `headers.db` (quit once synced):
    ./spvnode scan

#### Sync up to the chain tip and give some debug output during that process:
    ./spvnode -d scan

#### Sync up, show debug info, don't store headers in file (only in memory), wait for new blocks:
    ./spvnode -d -f 0 -c -b scan

#### Sync up, with an address, show debug info, don't store headers in file, wait for new blocks:
    ./spvnode -d -f 0 -c -a "DSVw8wkkTXccdq78etZ3UwELrmpfvAiVt1" -b scan

#### Sync up, with a wallet file "main_wallet.db", show debug info, don't store headers in file, wait for new blocks:
    ./spvnode -d -f 0 -c -w "./main_wallet.db" -b scan

#### Sync up, with a wallet file "main_wallet.db", show debug info, with a headers file "main_headers.db", wait for new blocks:
    ./spvnode -d -c -w "./main_wallet.db" -h "./main_headers.db" -b scan

#### Sync up, with a wallet file "main_wallet.db", with an address, show debug info, with a headers file, with a headers file "main_headers.db", wait for new blocks:
    ./spvnode -d -c -a "DSVw8wkkTXccdq78etZ3UwELrmpfvAiVt1" -w "./main_wallet.db" -h "./main_headers.db" -b scan

#### Sync up, with encrypted mnemonic 0, show debug info, don't store headers in file, wait for new blocks:
    ./spvnode -d -f 0 -c -y 0 -b scan

#### Sync up, with encrypted mnemonic 0, BIP39 passphrase, show debug info, don't store headers in file, wait for new blocks:
    ./spvnode -d -f 0 -c -y 0 -s -b scan

#### Sync up, with encrypted mnemonic 0, BIP39 passphrase, show debug info, don't store headers in file, wait for new blocks, use TPM:
    ./spvnode -d -f 0 -c -y 0 -s -j -b scan

#### Sync up, with encrypted key 0, show debug info, don't store headers in file, wait for new blocks, use master key:
    ./spvnode -d -f 0 -c -y 0 -k -b scan

#### Sync up, with encrypted key 0, show debug info, don't store headers in file, wait for new blocks, use master key, use TPM:
    ./spvnode -d -f 0 -c -y 0 -k -j -b scan

#### Sync up, with mnemonic "test", BIP39 passphrase, show debug info, don't store headers in file, wait for new blocks:
    ./spvnode -d -f 0 -c -n "test" -s -b scan

#### Sync up, with a wallet file "main_wallet.db", with encrypted mnemonic 0, show debug info, don't store headers in file, wait for new blocks:
    ./spvnode -d -f 0 -c -w "./main_wallet.db" -y 0 -b scan

#### Sync up, with a wallet file "main_wallet.db", with encrypted mnemonic 0, show debug info, with a headers file "main_headers.db", wait for new blocks:
    ./spvnode -d -c -w "./main_wallet.db" -h "./main_headers.db" -y 0 -b scan

#### Sync up, with a wallet file "main_wallet.db", with encrypted mnemonic 0, show debug info, with a headers file "main_headers.db", wait for new blocks, use TPM:
    ./spvnode -d -c -w "./main_wallet.db" -h "./main_headers.db" -y 0 -j -b scan

## Post-Quantum Cryptography (PQC) Commands

> **Note**: Falcon-512, Dilithium2, and shared PQC carrier/utility commands require the `--enable-liboqs` configure flag. Raccoon-G-44 commands additionally require `--enable-raccoon-g`.

The `such` tool includes PQC commands for three signature algorithms — **Falcon-512**, **Dilithium2** (ML-DSA-44), and **Raccoon-G-44** — plus shared carrier infrastructure and transaction helpers.

### Available PQC Commands

#### Shared Utility / Carrier Commands

| Command | Required Flags | Description |
| - | - | - |
| tx_sighash32 | -x, -s, -i, -h | Derives transaction input sighash32 used by signing flows |
| pqc_chunk_hex | -x, (-h optional) | Splits payload hex into ≤max_chunk_bytes chunks (default 520) |
| set_scriptsig | -x, -i, -s | Sets a custom scriptSig on a transaction input |
| pqc_carrier_redeemscript | None | Prints canonical fixed 6-byte carrier redeemScript (`OP_DROP x5 OP_TRUE`) |
| pqc_carrier_scriptpubkey | None | Prints canonical carrier P2SH scriptPubKey (`OP_HASH160 <20-byte> OP_EQUAL`) |
| pqc_carrier_mkpart | -k, -p, -s, -i | Builds one reveal part scriptSig (`TAG8 HDR8 CHUNK0 CHUNK1 CHUNK2 redeemScript`) with 3×520-byte chunking |
| pqc_carrier_parsepart | -x | Parses one reveal part scriptSig and prints decoded fields/payload |

#### Falcon-512 Commands (requires `--enable-liboqs`)

| Command | Required Flags | Description |
| - | - | - |
| falcon_keygen | None | Generates a Falcon-512 keypair (public key: 897 bytes, secret key: 1281 bytes) |
| falcon_sign | -p, -x | Signs message bytes (typically tx_sighash32 hex) with Falcon-512 secret key. Returns signature (~660 bytes) |
| falcon_verify | -k, -x, -s | Verifies a Falcon-512 signature against message bytes and public key |
| falcon_commit | -k, -s | Generates a 32-byte SHA256 commitment from public key and signature for OP_RETURN |
| falcon_add_commit_tx | -x, -s | Appends an OP_RETURN output carrying `FLC1` ‖ commit32 to a raw transaction |
| falcon_add_commit_and_carrier_tx | -x, -m, -k, -s | Appends both OP_RETURN commitment and P2SH carrier outputs to a raw transaction |

#### Dilithium2 Commands (requires `--enable-liboqs`)

| Command | Required Flags | Description |
| - | - | - |
| dilithium2_keygen | None | Generates a Dilithium2/ML-DSA-44 keypair (public key: 1312 bytes, secret key: 2560 bytes) |
| dilithium2_sign | -p, -x | Signs message bytes with Dilithium2 secret key. Returns signature (~2420 bytes) |
| dilithium2_verify | -k, -x, -s | Verifies a Dilithium2 signature against message bytes and public key |
| dilithium2_commit | -k, -s | Generates a 32-byte SHA256 commitment from public key and signature for OP_RETURN |
| dilithium2_add_commit_tx | -x, -s | Appends an OP_RETURN output carrying `DIL2` ‖ commit32 to a raw transaction |
| dilithium2_add_commit_and_carrier_tx | -x, -m, -k, -s | Appends both OP_RETURN commitment and P2SH carrier outputs to a raw transaction |

#### Raccoon-G-44 Commands (requires `--enable-raccoon-g`)

| Command | Required Flags | Description |
| - | - | - |
| raccoong_keygen | None | Generates a Raccoon-G-44 keypair |
| raccoong_sign | -p, -x | Signs message bytes with Raccoon-G-44 secret key |
| raccoong_verify | -k, -x, -s | Verifies a Raccoon-G-44 signature against message bytes and public key |
| raccoong_commit | -k, -s | Generates a 32-byte SHA256 commitment from public key and signature for OP_RETURN |
| raccoong_hd_derive | -p, -k, -s, -i | Derives child secret+public key from parent keys (BIP32-style HD). Optional -g (0/1 for hardened) |
| raccoong_hd_derive_pub | -k, -s, -i | Derives child public key from parent public key (non-hardened only) |
| raccoong_add_commit_tx | -x, -s | Appends an OP_RETURN output carrying `RCG4` ‖ commit32 to a raw transaction |
| raccoong_add_commit_and_carrier_tx | -x, -m, -k, -s | Appends both OP_RETURN commitment and P2SH carrier outputs to a raw transaction |

### Flag Usage for PQC Commands

| Flag | Description | Format |
| - | - | - |
| -k, --pubkey | PQC public key (Falcon-512, Dilithium2, or Raccoon-G-44) | Hex string |
| -p, --privkey | PQC secret key (Falcon-512, Dilithium2, or Raccoon-G-44) | Hex string |
| -x | Message to sign/verify, raw transaction hex, or payload hex | Hex string |
| -s | PQC signature, commitment hex, or chaincode hex (context-dependent) | Hex string |
| -m | Commitment hex (for `*_add_commit_and_carrier_tx` commands) | Hex string (64 chars for 32 bytes) |
| -i | Input index, part index, or child index (context-dependent) | Integer |
| -g | Hardening flag for Raccoon-G HD derivation (0=non-hardened, 1=hardened) | 0 or 1 |
| -h | Sighash type (for tx_sighash32) or carrier value in koinu (for add_commit_and_carrier_tx, default 100000000) | Integer |

### Examples

The examples below use a fixed 32-byte test message for signing:
```
MSG_HEX=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```
In practice, the message would be the `tx_sighash32` output from a real transaction.

#### Falcon-512

##### Generate a Falcon-512 keypair:
```
> ./such -c falcon_keygen
Generating Falcon-512 keypair...

=== Falcon-512 Keypair Generated ===
public key:  097fbdf35abc029089060d83188f3499383c4b4c91b7094d9e5ad7dfed34551faada699ba5848f26a66e1183fc6e7a530084b8b03fca774bea02426c0b855731037e73c30ce111bcfcc645882cc0b5d45934f26e101ed111880f122509042ba4dd979519069f82a7c39dbab56070998ebdae6481d4904f49b9497582dbd21c0b3af2547d80628e6c1a81779be40d25114ac194799ceef3db744e376485fbf795165556ee686a5c87ee00bc1ed8bccd6b30bd6ca0f3d7335dd20ef20a0ff447707033c9e8ac767435e4d055f539aa89629c683508d5cae6ec59ac4ec6a7499ee1409b88458a2e035aba18ce2bfdd38c6796a1c6e7d4710faac8076101a62785e7013190ec9fda0b1a0b19dd13caf4489816ebbe5e01e3dbdb9499645aa4c84e2fa6947298ec949207281168b35860a096a2f5bc020f65fe2d91930b493aa8a8d775add786c8fa51b44b4276754a25e9670db9cd5edb3564bb3eb908e03048c951b5d54468077ea3163a4ae34ce33fda96c12eabbd47d2c98231d2338a848f8b3ec45e8530e358fb914e68f0d95890165c585ebb82119a537405add3e7a66d64d6267aeb6543582474d13360052b1a8042a74b12448e3a726de2b15a80cf03aad9ff9de10f9a0a0f4f3bcc96f9c883a00de6ead55a63e19e01989201c719433a5719b4a06b42e65755ce2650852e9c419e84c0107eb625e34f8b5d99e0a794878db28a8fe5b354424412a1b0cf536a2f5447e734d35e3ed080572be26d10496843752d59b006a476f4ef9c670ccf44629596077409b197c65a713635cb682326a9412c28aa458e6575e13aa221f6b9383d80084aed72c4ed934047dd9f7458a865942362d29605d0cd240c7a37db175251914432f9b3a21e8045423ae7a4b721808acab68849227ee57690e7a2853d806aac688d74850f91199b45a4d417768fccf056ac875b43889cb8d1cfb62350de2d98e632d8ac3b384e853358c32405eda5b48f69b700a22c508cd50c21ed7c906fae25a1eae93a4541e7b7707a478d538ea49da9734994b7294a3f725899bc7b7c9daa2e8c0651e9b3429b4cdd88bcaaf4d5d674667a73f9b0603a9366c0f62b4a46b860d47b83c25842f849bb8005c661f43e67c8109306b2e0e3caa1014a9d3277ffc7bd03783296f026aaadb40769f00f048fac83242ce2f373185fc5f262548acebcb13f4413236d6d52145a1449a895d0560d644df41c15488447710e7300418ea47b4dace0dcc01b54de8304c686f7
secret key:  59fbcf46f7d0040fbf80fc1fc01bcf4407e1040430c2fc1f00fc203bf82001f020bc040181f42ffbefbf40088ec2e03087f3a180002080e7c0c50c7f46fc1001084f8010207bfba04510600103bfbff3b044fc004108410317d1840000450fdf4107e1bff00f85047e41fc913be8003cec1fc4104e81ffb18203fe7b0470c10befbcf7defe101fff0c2ebae8723efc2d7cfcaf000c01400bdf83137f7fffbfcaf0213ffc2f78004ef91bd0812800c20b70bd2c4f3f0c3dfbf3ce3c0c5e40f86fc907c0c4f40006f02106179fc300110407afb7f42001f80139efdf43145138f4aebffbef000fbf3fffe084f01ffceff0bf13ff83fff07deff1c41410bf1fcffc1b7ffde431c0f840bcfc3103f010fdf82f82180e80fc2dfbe86fff13f03d03a23f1b6040f8117c1820441c6ffa042142f800c20c3f45fbf0020c7104fc103bf42fc417df850fe0fb083f06086ec21c1048f7d244f47001ffc23e03bffe23f184084fff13c081f0104513debffc0f7ce811f9f4003be39efc044046f480fff80f4c042f3d083f41e7ff8207fdc3f88f03204181fff13cec007c143fc4142081f811bd1bdfbffbbff30c7ebf17ffbdefc0fcdc4ffdf7a0fc18207d17efbff83ec40c0040fc10fe285efdfbeec0039f82f06f870440bb07cf46fc3fbb1c30fffc2efe1011f8f41178efd08203e183041e7eeff045043e0010108014af03006f3e07e24007ff82fc0000f81ffffbe13e0440841fbe7b102ffc102fc0080fbf103006f7cf470bf0c0f7f046ffe041083ffe0fef7c1051000b90f7183101ebf0c22440ffff9e42fff07af05fbeefe03bf7bffe04017f1412bc004206f7ff7cffa00207f1fdf00f0403ee7dfc0081fbb0411410fdfbf03efc3102f3f078f421ff0c2e79fba000f7d040fff23dfbff4113e18203f07efbb07d03df45d7febce8303e183ec3082040076003fbcf42ffd0bff85f7b08503f07c2c1ff723ffbdf031bfe82fc0f8300013d0bdf3d1c6f7fdc0ebb139f080c007a23c10cfbd03b1c4086dbaebbebb0fc0c3ebf081f83e00ec2ebee841fb000101fc407c0bf04007cefde84f43f3e0e0ad20d1ed9d71415ef0503dded1bf7ec11d4f1f323d4f4121cf11a16e5d8f2d1d40c0002f90befe9f414e70bd0f91603e808f52514360bc006dad61ed3f00a2935050ff91be607c921e211d713040922211cf5fceffb210bd510dbf6d7e9efd50303f2f0f5150519c8f31f29f9e5e430e4010225e5fae4112d0ffbf13c35ffcd310cfff806271ce1ffd90d1aeff924dfe6dc12f3f4ef0b040ddbead4cbf3082fff18fd44fef8ef13fef718fc0916f70ef5010ae113fcf9cb1329f6fee6e42010f1e00322eb1cf7fc1c240809011b1cf0f1e416060410d8f4f302160fdfdbf81ee6f1e0e7181b0d270b0ce5f61423d91ef315f91a1ce6ea3504db3ed7fbd6f8e607004de62eebef100bf3f1252011d9280909f011e114f8f51c1afbf006f010e3fafcfc09ebf3efefeef20915f5f8091e18e4f9ed1d050aeb01f5de03f7021a252604d6f4f0c8fb08d10c0e0a03fcfeedeee9da0aefcddb0bee04ff14c9f8f80eff1b0deaf90113de1c21fbf00cf922e2fbc22b05050c15f831f3d5ece1f8ebe314bcdd28f51ce70309ce0fe7da08f7fbff190c0d15f306321f30e9db11282e00222f0531faf5e6ffe61f1617db0d07e8fcfe05081403f6eb00c612d5e9f8fd2022eb001b060ee3330df0ea0a0602d204d9f9e0e0082e0a11ecfa0af3c811230dc80338ca08f803f227043828edb4f0f919140d0438eeda01f3f9eaf0011432
pk length:   897 bytes
sk length:   1281 bytes
```

##### Sign a message with Falcon-512:
```
> ./such -c falcon_sign -p 59fbcf46f7d004...f0011432 -x deadbeef...deadbeef
Signing message with Falcon-512...

=== Falcon-512 Signature Generated ===
signature:   39716b58eb2e5c04be0846331f113da9021421e926a0513160c623ed1841d4dc134b46c964fc24763d10e277fbabc94ac663ec07ab50ce5a7031e9776238453424921f8484e4d8439771bc2919b927df0e791f56525a6d786d4d9a69c24e922c32a781c7ecf392e38734a31f086c052ed3d915d49d9c976f747ed6ed6090a2b869f10ccda4f9cc727870095e653ab754ba59e54fc2801d228ab91c359a3af4e91b03e2d0a2bd4b550b62889147c7029b7ab999447e6bd1f2c7dc3d4b3be5417116388ced2283cea0641e42a70c1a8f2c43b431e1ea23f1b77753da7e6b952da5397733845a7112b4a175063cb94fb282375274d974036a73989e7b9f6a57f2b10280b5d6908da690f1cde7e9a2c16e85752598c6b256b19e4dc2f50efcb2558c4c8d909cd02db81e7495d3f07cdbbcbd11f3cfa8731fab7db05a0fc2e433391908d925283b6f3e523984ce66c0153e878dbfb661b47ad4c7a92c79c93bfbe391ca9db9f53fd2d87df7ded77a2506436efc36458e9642d95daf2e7c8fbb30a7011f1c2235d652dd7b6b34865e275708d629f59c3292fadbd3016866121bd4af6b635394224894d35b1eeacfe7929e17ed986184ea75fad7a06d832330930c8abec2b2b7da0505bba7903705926795ac7afd12c85be978f95085b387810fbdc436579d73810984312611fb6879b92a5c94ed2179d484b2f6b825c9af56569f5f76f467dd6e4349f420330c023f29507bacdce227b3cc74f54a7c54953d91e423f99dcf49d3266a3040d7495128288a07aaf55cca1d1804f306aaf8fbd352c7943098deab90e7bfa931eeacc3bb2bab432563924d230a4d30d8a502733388d466fee77e1f28c4e2a7729b99fcd5ca0dace114e5ec5bc9b521aafeecac4ccb3692cd5306c18a5fb1f744eb43b06fa088
sig length:  654 bytes
msg length:  32 bytes
```

##### Verify a Falcon-512 signature:
```
> ./such -c falcon_verify -k 097fbdf35abc02...04c686f7 -x deadbeef...deadbeef -s 39716b58eb2e5c...b06fa088
Verifying Falcon-512 signature...

=== Falcon-512 Verification Result ===
✓ VERIFIED: Signature is valid!
The signature is authentic for this message and public key.
```

##### Generate a Falcon-512 commitment for OP_RETURN:
```
> ./such -c falcon_commit -k 097fbdf35abc02...04c686f7 -s 39716b58eb2e5c...b06fa088
Generating Falcon-512 commitment...

=== Falcon-512 Commitment Generated ===
commitment:  f6cfeea6b151e82b2fbf8b775ea045d7f923efa14e91711a5099c522f105cd46
length:      32 bytes

This commitment can be included in an OP_RETURN output:
OP_RETURN script: 6a24464c4331f6cfeea6b151e82b2fbf8b775ea045d7f923efa14e91711a5099c522f105cd46
```

##### Add Falcon-512 commitment and carrier to a transaction:
```bash
./such -c falcon_add_commit_and_carrier_tx -x <raw_tx_hex> -m <commitment_hex> -k <pubkey_hex> -s <signature_hex>
```

#### Dilithium2

##### Generate a Dilithium2 keypair:
```
> ./such -c dilithium2_keygen
Generating Dilithium2 keypair...

=== Dilithium2 Keypair Generated ===
public key:  3d438e7f8d197605bfb098264316c104808c545bc178e8382cc60d4d506d311ff7c1f77e2110385ae87ee4024f37bedafda56cdb01f41f4b8a18737bd23a0b5f27eadaa9db6c88146366cf88a669f2f15b18e59330f318a36386ff9d547257d79b98eb1d7fb0d3d4e56d90a461cf1c8efbe932161cda2d869b700eb0a9860e86284ade4a1153f8e3e597b3dca7f6dc637e8bd05f107fae58d54459acf56b7cd63beb5256213004482ce6ff65245e394e19e18835a8431017da2333eb3fedff4db55f54a69f0fb1022edd86a1c2f9c070ef023de3cae4d2b93638d179dfc8356a63776ae3683c1abd3a31e8e566e6160430eac50ca2c6a171674d026414d77c27b76227438d22c2432cff36b5c8b877ab950468e98eda2ced3159a6e2e31d52d27f4177e4f31bef41b508b118ae05cd75a0b61c927a9ff2f083a9056cebf67ecf9606c574733039ce60dc2cdf96872c4c0670be75935ed76e570092507360e1f1618e3d676bba92520eb9b578e15dd3b44ff28993ca0b1c822497f01d9f6e47e74b2f7c82d33600711d1840d42113e2701c4d2c1ccf079dd9f86fa9e81d9444f59f3558164d3431ab09e2f1ea7c516b3f978cf93907a58c5cfc3b93bafc40d14354ca77332aae03079696b5b7d485c2cec16e257b1c9d50e0df347faee0fc740e37644dac9335bb1d60a8ffc02b96219082825fbbf4143a3360e262d5769446b5aeda853db4751766723e359ab63ccdd1c3013511dd0a4b45f2f8d99952e434d1e53fd0cc22af646cb22b7ba0858ae661fb45bfd21a89f3307efc9a4240e1bb9d0eef27eed1c4033fa1d383cb5f27f6d12393108636257f32f8423239c37ad6c5af87b67eafa011ac455948563fc345770a005a07531b83da847f7bd81b70d959833d1085af2c9d750a4a17f403c64f23d8eccb73f6bec446b296135aafbd011e6ec009a0b5014a623162b6d1d24c44289dc5dbbfe0a3141c06a0fdd7b43f82fe755911e901066bd4d3652f75ca526b0383af5e553a0aa28e50380d485097d49450ea4b21df45d1560d8298ab0eaf4bb502609490b7157cc9723ac962b2f8bff5bf3c27506777c7c5b54bb4ddf043c0dd3f252ab7a6625cdd7c38843bbdd81d983a3a29fac52ab45afeedd3a7612b783a7f832c2627c99b04a366eba17faff6e0b947c5192a781e0c3d31d7299f3cce7ab240f23c8374c584f2a6af824c6cfe86a00c29e1ad10c73785d0f26b27d3081619ec253133f37a0a25a348728cc20badbbf3be7d37e131695645e93927bdf4b05b76a8829979cdd8bc13c2047ecff1cfbf8ce5fc2394b844811b712441823b1ea742065097ca16f187d6b41994ca71a118891e38cb6dfab0763d54f17df75cfebfedb388e7776ced94149da1a7285a3d4879306653aa5f3f65a42c2d4dbe57990c3e1124ab44846c6f59fdd1d955935731cef934f503210ec096ad9b463a94f070d687892e696252b5751757648f8ccbe7f3faa30eca1510fc1c5632f670321b034c0623ee12f2d375f5119f3e7765a2469b4095d2d68e440702c4a34cc346435fe1966cdeef884a29e9f2cc4bb4f2fc2f676aa944d1dd8bb499341506d68205e587a997ec4ce82d822cce44500644aab95df1dbbc6c4599da96ada8abb53549e1a2c0ef394d6cae276b93133c2f705f8f4664cb55046afc42135be7cb259444fbff52e73495f5dbc5e786bb6f5e5019af8a848b7187aa3a8f5803d7406e946db6efeb2ea227fb6b7bcf6d7253a1b0cbf9398530e419173775d8b84077b7a77afc8954c6ac10cd4b2c9d96e49dce6154e77a25e24cf09c4cd1b02a7fb75266cccf126a8ab0561b50af3f0101611fbf21
secret key:  3d438e7f8d197605bfb098264316c104808c545bc178e8382cc60d4d506d311f55554cb999be278997f5f47890a5535dbe20a1ec9889dcd7f2f9fd81c13ffb843f85507e464c228035419a9540eec4ba7fb45704f7212e7f6b2ddafabb0487d921f30b8d10fcfe2f10e92ea96f589f5ad542f687c75b79bf9b02a7dc1fa8c54018160240809114124e89a845008051cc323208b6919a203162928514c609e2146c40160850468a40400451b46188188982486e114852a2a864112482983492ca122122454e24394e844409208751d200855bc44cc238259a8670081350dca245c9b061d0940511052e0c29640bb391d94481db366810873043288c10b830c1362c19457111c95100416d40340c1a360c23a9280a2865dbb48422338502084082200c12a821140006db927103136463b40c48b4280ca84958c6491c3122243348c2846c000404624420e29885092268d48805c2a0610b882024a041a3448a0233710b210504160e21402c24c3654932088444699c326a98964148360e88944c40a42103058614395150c8881aa56d91820001b20dd8202e0c00815b200cd114890a314808860c09250d62b050d0186093a830dbb28de216710411521c924811b6680bc11049086e61a66c533084cb420162300411138a93102404066d1248284b448d82246e8b246d42280cdc4222db204e1b997041b46802b82861443220a90ca1a231caa02d52342c8936446212860848201120841436692216251133266348628c88888414251930002228884a424280162c61b2900a923018a54801440c24310d011441129165601001d1346921c308a4c201c40612208408633001d90886041972daa248413666d3866823226d9416649a226913812080322914b66d61a068c2c009c1024ad9142263264c410868d8124edc98204ac03004082ed1c06924a85121c28582102560a600dba02808280e5442090c07311c23490a8564dbc26c243810d4006553802c22944d1cc60983084adaa42ca28600429645a42004ca060ea0008d4ba008cca849e4025249320900342a9834705b02025128324c9091493012e44852841600e00442cb342cd814710a39485b2692121708e210801c8648e2c605243186001901812842d18090d24406a4366d41240e23070e090325243069198289c4b82d611881a2a004c9040e8a3290cca484d8968822c12589820c193511911272c10032e04409902005d8a68d14259209148a980004c3866cc1428ed3e53974d53fd37d5036f1df13b38f58d39409e790daac8d167657e4ebc82b2e2ac87b97467a841d5eeb2a18b4404e592d3be1899673a3581dea06b9285016f58b3324e99ffa23eed5e83911a0fe5d0bdf0f3cf64fdb33db12ab2d6bebacc6f3a3269483ad5e238544192dcd0a2ef903d2d9dac2b69184fec01410cc9cc985e635da8bee95bea26a08cc8148dd0281ea9a5aebed88521c798f59cc46925535137efe7cc8704d23e11d1fa2115ba403d2af098f8fe43769c1d442a4becf88ba9f8afed39ff5702fa69de1bf3aff477735c8d7eecb29d93c3ecc8d33b8c076fcb0f1e1c3d88be18805f01e88f38d21faeaeb532fc0600d31f562ed64c4f9e952e22cc27b49930b5c53f8a0057efacc6f0d6b32f6fcd46889d4af54db0bad6e0f52ba4197d5712479a991da873f9b8bbb0e9060c95867bf665ef394ca1d17d5ecfac7990b208e277cf59273c4963a3d469c643ba5c8d702225b7bd62235d80845364954277b00e7b61a68ba6d28da7457fafefd504c1b3ff082a031795849dd25e2d61c183fb5fd7b8433de39c66dd5694d10b4ca36c8638503d951eca2b4ffa16c7f9758657de6ee608e52bf1192fd4f2b134ac787da9125f88d25f8f26f6537cb126324ca139d47e137d66165d89dc5495733987872165f23a4df722b99c55690856e099054ee3a8fb816ddecb30a6ee363b730920d5c028f350fe0a8c72b2c2ab5257a4eb6175ac02592b731dcd8f9309ce832c17eebc31c16f83b7c66d01fe4c9966c9bc2b1be83c76ddb5a055c87439b8178788b7823301702df2d86719a94f8e5ff599d486e7b3c828d83d69e8005a80172f9f249d8499c4786368af12e0b9f98db85672452e0f3ba9835051093e94f4c3b03c797024021a442ebd1d349b5e713817493362d1627b496339d01441eb5d48eb62554229e0c63105bde69fb7e2d09b924295132ce677047b506e4e0e434233533c142dc935e751150ab869df378c6bf73865c91eb4424dd7ad75c7ff04bce6b9b6e85a3f10051ea1ae77d25391780dd66dead6ee91f81a6d31356a0f327d5f6b616692f0287649d70918d39f56899b1964e1c24e707ebd7d55244ffa264a76c15cac98669099c4b3bc42711e967a873841475796e5805cabc72ad873a3fd91476eb3fd50c43dca4a2d9876c811f8f10d75038e5c9363707cc93504c77193d42705e7cc724d7e6c7deccf577795186731fb1afe5b7a6c050bd67f1b0211844baa6551be5839d187bf75fa8a43d73a5d4979729f9035131bb6f0fad0de283c70ee6a822152df0bda491f7b733f13ab5925f2b73c48a9db2954a3233f2dd9df7162f60c61d541ce0c6288e6007ff2707a6b12e27b9dd74601867ee6d17b30ea295977f2e8d0929586949ce5ff038b8fb225aea5696f156dd6754b6359f71f4d7493771e15e6bca1e0d404fe94c99cc7597160594964b391d51925bcf05027a515cfdbbffb62a9c69c0296d910517e1cd6db1ac1fab7dc7e19f71faa4c61f3c0822715bde5da55e16b22ed7a81821c8043588acff62b847b255fcf1b1818b6a8d2cab0f39361491d36c1c73f572b0124a7d2ebd3c83806b2975d40e434cc126c2394fce6e47f0c37df8c7ca0572df3cea102c589d7f813d0ca81d86b3421b1d679c068dbf804b0fc7ef1ace8a8539e289e2686f1e34783adbfee475285ed508eacd1ef60341cd628875ffcdfce5b92080b1897208c334377be34bc3d0dd8c4140797dcaae3c3474edae49fa22d88131a8ffc5441dbd044d3fa8c72098959055148c82c175a053d1bcf44d8d8c3573fb6b25f71466cfc9ce79b8e8f11284964f01c0b5717b5b5333a853f30ab43a130e5292db845e37ea76f3d89eaa127d9083a77643c8f74abf90a190c40a39c165af43197d8fb0539595fe98c493085ac62f88697fb6ad61c05ac66d667fddffbaf8dec79d178f874ff7e52f7766f3b0e43f53882cda758bdde7a31fc374bceed7fc4573fd7948f081c6630c16caf68403164282b0967714859d7a73255b932dedccfc7fe3ba60213aa151fe10000406112126a210b15010f7c49ce9656ff6747459c5c93a77b21874d2fbd836c79da8f4a49bddf1d252c186af4a248023e5f50989c53849ad64dde14b52aea7a2d43310a82987ed5d6bfa03b8a94e8d02127968e69de680211625d6e5fc98cff4eb42ac8a4312048a313d837f3d6f86ef6a6e61677d8232b50c64f99d36265c7a9790c25e3db9cf188a037474330e4317b1ce280cbabb08574e383d7fa99c72b337c58c518ef95b2b2e623bc64905bf60ca2ff06ecaf9fa40dbda86932eaac10cba4e785936115afc7f86352c06a16a9a07c1ae
pk length:   1312 bytes
sk length:   2560 bytes
```

##### Sign a message with Dilithium2:
```
> ./such -c dilithium2_sign -p 3d438e7f8d1976...a07c1ae -x deadbeef...deadbeef

=== Dilithium2 Signature Generated ===
signature:   7d305a3d9edc7c088b5071b54fa1be86644badb9d57cefd263e3c96dba538051a6d611ebf9f06ca4452928dfe87ac349d145cf29722d4efda3f020b1b7c9151ff15eb70e6be0090e0eec4bad4c41f63bd5c99ec1aaea561a763fda87944e30481eda2cbb3ca4e8e048155d686153c01988e62d85ea2a608cd7b47488b98269d57925932951db8dfab2e1eca85a2056936c6af704fabf63f968a6479617f83e89e00dedcfad719fbd338f3dd44db989849edac33524a67c5d6e5c06a9752100e32af01c42efec9ed7ad2a358425f8dc99740a84ed0bb8785da646269a278e3269587ba05fa0756f83f5f51aacd642b7813627571547b66cdb60acfc4d4d778e592d8fc68046001d4c5e2e5ebc34e6a44f4698ca53f0a791779d63208652a8fca0e1e6627c5ebae5a97cee9abf7e2d229a54ee76c198890ad186cb6ad2611b183965fa187a96c5dd7e2cd6b9485b492b9910c6ebc0a131521c4d7d0faf1c73f6e68ff38b1bc1c0743630fabd5d4afc8e832af84fec092998fdf7c36fef3d0bf94092522ab1f57ff96c700a1c3314289930205107b32c634a602e12bf9c6ab87c64df874fb964c9348af9e723425b252a1a2e4cd3c63e9342a4df06f2a2ed3b06436899c31770aba31dc3fae0654b131d30c5ea2291f7b5b051318955e705f7bd714b0d173765dd69423eddb99657df26ae81fa0bd8f6c1028f64e02b36d4ab885710b79c4331f882e06507f2be917d1b8382671cb41c78e686e3110e2d011ab810151e6919bba3d1dda98a667b468f8d10a9cd61e85f189c7be51a4bbcaddba7d6ad293b88036d336313e4030e615ba537cb7682a762e59f0a46a76f5eb1634e1865ba010e561b862965035519aa297f1177a4d788a87f50dea839a216d5ab232f5da9372b4b8879ce24d05016870dda1ce63b4a5458dc8200875d804686829112f03e6ebb9c89829377e3a90f0c35eb59b9c9b9522404250bb51c96d3c7061a86088565e20e3ce3094c68c33b39d100d3ff06e483cd13e8a4c32c026f03a12ac083a60e4067a90e0f22682ae81d76dd370ab3d1dfab7c6eb00f98fd57c6ffdee6fce2b4025434b2e717a6c7173250aba9d39401f9e7b5b0e4d1a28cb8b4beba1c7d924cece9c7b9ba8875c9409d60e1f282c26cd0d1437cd1763a07cf14def4f09b39395027e1fdec6fc717041f1dd785498a638ea12c9fcc2dda56ac3428ee5fc3ac5a0087400bb3bc1518968de7a93dc84a770d6d7e4bf051c43170d01f4b419deded5af3f7847414fac77e1db0301e5c2db47a52bdc703742f6e1432a6c43bfe3b3f75942cade6c61b43ebb398d9496ed319d6b4bfc59c92f5d5c2e3447e9035b865e10412913c07e8add58c536dfacce753c8bd9c953e7ab414089e662ad33902b717b3da976859f0daebdeae3fab91af1c172a55e5144f633dd1fbd12dedb76375c5c160d0ea4cbf7ba6ab2f55035b58ea6b5c8a78dc52b0f2bce30753d5257af61e14aa6f1508d6bcde0fbfa4d1658bb66cb25495fa5b5128c56307608168b5d6b5b71bb380d17a7f6fe6078c911581fe9640e6d3cb197b5c39a4e23b7a49b6cef293b978ae1f641b473180f18260fa89bd4dfe533b122df04a7ddeb7fcb09f4ea7d032c8ea242193b222d8a6ff51c6363b8214b2d371dd760199a9038ac081975d2e1597c45f8feb8453944767254ff6dc11c1820924c2ba99bbfa0ba2499674d98936b9431d6b6616bb36d6eba0537e8b4a5895138b932077bd09b9bf53ae4854d3362c701bd8c27aaa114a53a1905721a4d8eafd1d4001e31f6a6bde71a62fc2f74224355f984d443646cb0e8ba8113e3261fc85012562faa92b39a9dba306e935dfaa538a5c8b98ecd3369a63bd175158443e965415bef7a9c243acb66d53788fc6b4bfa08ce701c647ac905d683e45eac51128c7829734af492e1bf55129f11e24fa27fb9607e48ffb00b955584b94be0b669154f281c4413dfab7471c9dd1ed885369d7434561e2485384a8ba97df9b143608778b607c0d02fc3355aece8d41c57dd26fb199427d81aaf01786dfe6d4cd4bf61d162cdac01f883ed7e12cd259530e3c9d871ac8f35090d00a3f09889134f649318c1e8bb9dd55cac555fba80a99634befef325554b42266ea02952ab790d3b148a1ac9627fa3a24a131470ee1463b5910d14b8435130f539ec4bdb07d6ff7c138dd28e7c3ff00d992ec50889b246a3db8512abdf8ef9d13c0273d738c616b82abd464e9ffc69f084f973c01fda5a799acb3545d73009466e2075c6a9be6d5083f1d4083800c3fb9a02dfcf24a960249bcb164a96d764fbf39a820690c67c2cfc792d0b0b42aec8a71e6dcb03889ed59eedb875bd062ba86161f4224877936dc147ecfbc24bac67ecc209c1bc085747f8300c0a217ec45c25d76709c5826adec9f6df3bfc651a8d0ffaac3e076b014801d99290cb921c64ca7c0c4fb9615a448cb01fb33ac9d646a804f3db093a06e72c3e72c6f78c87d47c942e0c97ae418f11999b3b9e56d9f1280fbe8abb9c059d49ccc0bb47bf239f0bb7ea612ad73d3138cc04ea01be268983aae8b69deeeb4a9d47c478eb3cc9fad0fa8a458effd9a97dd50f6e273e4eb37afcbbb416d014cda7a2cca20ff13e95cca0d6fd727c948c2d606785a5425e990db4d089466755bce7c1621ccb626d6b91c5ffd0cb58b5012a928e1bf3d499257ada0b8c8f20e1db719c9e320315ba3ac9c9ed637e7caf46f5fa5ac590f76adf66f4a66af0bfc0aa483bd0682027722022126104b84253e20b7b8826c51107a7ccb05fa9b5cef29113e81c3ed1a2d9999d49938fce06e2a0118ee874b2240e23ca72544e9dc5befc4258fcc7fea40052ed91991109aca131da2a5affea0aaf5f8603cd4f587b0e80a95a608e9a1287b691a059807ebaa16c9fc448e934689ed330715f280842e760a9f2f980c6f05f13a150785e79deddfb7be3feb3f67f06d0c3fc36a84214d75a1cee924d645ddbf3b46b8580b6fc9ab65ad66895bed258de245cfdfe1bd022757412e13ef89aaaff4512db51a2ec3d5937fa7be1b8df326a95f944173f212182e4f4a0bb5ce8a2f48cf8ca00cfcab79ffbd5258f719e9823606f65e92676da5dcbb265f0343ed6bca065d52bfb1203b7a72d3d646f4b76b0ef3fefe1d93ec71433dfb6ab8c58f766f5cee27a80b56ed37059e01038b489ddf570ac8e2f782e56d1d93a34a30fb4b02d0c0a3aafb7274838e3ef926683a0e4460fdc89b1622f409a2b5b515cd3030f554f0a976d7438f12bdf552870baf33e00a161c3f65677586a0d5d9e7ecef0319274f5a7ea5a8f0ff19292c30324b4c5463708082969caec2cad3e1ec35456698a1a7b6bce4eeef000000000000000000000000000000000000000000000000000e182c37
sig length:  2420 bytes
msg length:  32 bytes
```

##### Verify a Dilithium2 signature:
```
> ./such -c dilithium2_verify -k 3d438e7f8d1976...01611fbf21 -x deadbeef...deadbeef -s 7d305a3d9edc7c...000e182c37

=== Dilithium2 Verification Result ===
✓ VERIFIED: Signature is valid!
```

##### Generate a Dilithium2 commitment for OP_RETURN:
```
> ./such -c dilithium2_commit -k 3d438e7f8d1976...01611fbf21 -s 7d305a3d9edc7c...000e182c37

=== Dilithium2 Commitment Generated ===
commitment:  2935837d2f042abe70669a893a0c9b7f2724007e514bf6c56bce27c54cf0909f
length:      32 bytes

This commitment can be included in an OP_RETURN output:
OP_RETURN script (prefix 6a24 + tag 44494c32='DIL2'): 6a2444494c322935837d2f042abe70669a893a0c9b7f2724007e514bf6c56bce27c54cf0909f
```

##### Add Dilithium2 commitment and carrier to a transaction:
```bash
./such -c dilithium2_add_commit_and_carrier_tx -x <raw_tx_hex> -m <commitment_hex> -k <pubkey_hex> -s <signature_hex>
```

#### Raccoon-G-44

> **Note**: Raccoon-G-44 keys and signatures are very large (pk: 16,144 bytes, sk: 32,272 bytes, sig: 20,768 bytes). Full hex output is truncated in the examples below — only the first and last bytes are shown. Actual `such` output prints the complete hex strings. The example byte values were captured from the in-tree `--enable-raccoon-g` backend (byte-exact against the upstream `p-11/lattice-hd-wallets` reference; see `src/raccoon_g/README.md`). Raccoon-G public keys, secret keys and HD-derived children share the same 16-byte `A_seed` prefix (the first 32 hex characters); the differing bytes are in the remainder.

##### Generate a Raccoon-G-44 keypair:
```
> ./such -c raccoong_keygen
Generating Raccoon-G-44 keypair...

=== Raccoon-G-44 Keypair Generated ===
public key:  5166c7c3ba5be0aa4da46150890f0b3d...<32,288 hex chars total>...e4019816454757dc014c450405f5b601
secret key:  5166c7c3ba5be0aa4da46150890f0b3d...<64,544 hex chars total>...00029043000000000254000000000000
pk length:   16144 bytes
sk length:   32272 bytes
```

##### Sign a message with Raccoon-G-44:
```
> ./such -c raccoong_sign -p <secret_key_hex> -x deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef

=== Raccoon-G-44 Signature Generated ===
signature:   7a6f30d5a0130a4c2e24a5481d0355fe...<41,536 hex chars total>...ff070300fe0702000600fd0707000100
sig length:  20768 bytes
msg length:  32 bytes
```

##### Verify a Raccoon-G-44 signature:
```
> ./such -c raccoong_verify -k <public_key_hex> -x deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef -s <signature_hex>

=== Raccoon-G-44 Verification Result ===
✓ VERIFIED: Signature is valid!
```

##### Generate a Raccoon-G-44 commitment for OP_RETURN:
```
> ./such -c raccoong_commit -k <public_key_hex> -s <signature_hex>

=== Raccoon-G-44 Commitment Generated ===
commitment:  b36140f6a30ac6fa0742bcae1704c81f7a584e89ce5bd60cac989275e94e4c3e
length:      32 bytes

This commitment can be included in an OP_RETURN output:
OP_RETURN script (prefix 6a24 + tag 52434734='RCG4'): 6a2452434734b36140f6a30ac6fa0742bcae1704c81f7a584e89ce5bd60cac989275e94e4c3e
```

##### Derive a child key from a Raccoon-G-44 parent key (HD derivation):
```
> ./such -c raccoong_hd_derive -p <secret_key_hex> -k <public_key_hex> \
    -s 0000000000000000000000000000000000000000000000000000000000000001 -i 0

=== Raccoon-G-44 HD Child Key (Private Derivation) ===
child index: 0
child public key:  5166c7c3ba5be0aa4da46150890f0b3d...<32,288 hex chars total>...b500ccffe7b0a4fc01c4c5f2efd83400
child secret key:  5166c7c3ba5be0aa4da46150890f0b3d...<64,544 hex chars total>...00028c4300000000021a000000000000

> ./such -c raccoong_hd_derive -p <secret_key_hex> -k <public_key_hex> \
    -s 0000000000000000000000000000000000000000000000000000000000000001 -i 0 -g 1

=== Raccoon-G-44 HD Child Key (Private Derivation) ===
child index: 0 (hardened)
child public key:  5166c7c3ba5be0aa4da46150890f0b3d...<32,288 hex chars total>...df01a1ba860cfbaf008048af21713200
child secret key:  5166c7c3ba5be0aa4da46150890f0b3d...<64,544 hex chars total>...0002ee4200000000029d430000000002

> ./such -c raccoong_hd_derive_pub -k <public_key_hex> \
    -s 0000000000000000000000000000000000000000000000000000000000000001 -i 0

=== Raccoon-G-44 HD Child Key (Public Derivation) ===
child index: 0
child public key:  5166c7c3ba5be0aa4da46150890f0b3d...<32,288 hex chars total>...b500ccffe7b0a4fc01c4c5f2efd83400
```

The non-hardened private-derivation child public key matches the public-only-derivation child public key (same chaincode and index), demonstrating BIP-32-style HD consistency for Raccoon-G-44.

##### Add Raccoon-G-44 commitment and carrier to a transaction:
```bash
./such -c raccoong_add_commit_and_carrier_tx -x <raw_tx_hex> -m <commitment_hex> -k <pubkey_hex> -s <signature_hex>
```

#### Shared PQC Utility Commands

##### Derive transaction sighash32:
```bash
./such -c tx_sighash32 -x <unsigned_raw_tx_hex> -s <script_pubkey_hex> -i 0 -h 1
```

##### Chunk PQ payload to chunks (≤520 bytes each):
```bash
./such -c pqc_chunk_hex -x <hex_payload> -h 520
```

##### Canonical carrier primitives (two-transaction TX_C/TX_R flow):
```
# Works with any PQC algorithm — use the appropriate tag:
#   Falcon-512:   464c4331 ("FLC1")
#   Dilithium2:   44494c32 ("DIL2")
#   Raccoon-G-44: 52434734 ("RCG4")

> ./such -c pqc_carrier_redeemscript
redeemScript: 757575757551

> ./such -c pqc_carrier_scriptpubkey
carrier_p2sh_scriptpubkey: a9149b402803555511d15d81207d3e2cb3e6bc365e0e87

> ./such -c pqc_carrier_mkpart -k <tag4_hex> -p <pqc_pubkey_hex> -s <pqc_signature_hex> -i 0
carrier_part_scriptsig[0]: <tagged_carrier_part_scriptsig_hex>
carrier_p2sh_scriptpubkey: a9149b402803555511d15d81207d3e2cb3e6bc365e0e87

> ./such -c pqc_carrier_parsepart -x <carrier_part_scriptsig_hex>
tag: <tag8_hex>
part_index: 0
part_total: <N>
pk_len: <bytes>
full_len: <bytes>
payload: <payload_hex>
```

### Testnet Workflow Helpers

For end-to-end testnet command flow, use the provided scripts:
- `contrib/testnet_falcon_test.sh`
- `contrib/testnet_dilithium2_test.sh`
- `contrib/testnet_raccoong_test.sh`

For end-to-end mainnet command flow, use:
- `contrib/mainnet_falcon_test.sh`
- `contrib/mainnet_dilithium2_test.sh`
- `contrib/mainnet_raccoong_test.sh`

These scripts walk through wallet/faucet setup, key generation, signing, commitment generation, transaction construction, canonical P2SH data-carrier attachment, and SPV monitoring commands.

For non-interactive execution (recommended for reproducible reruns/log capture), set:

- `NON_INTERACTIVE=1`
- `AUTO_BROADCAST=1`
- `RAW_UNSIGNED_TX=<unsigned_raw_tx_hex>`
- `SCRIPT_PUBKEY=<prevout_script_pubkey_hex>`
By default they run on testnet (`NETWORK=testnet`). To run the same flow on mainnet, set `NETWORK=mainnet` and provide a funded mainnet WIF/address context.

### Automated Testing Scripts

Comprehensive testnet integration test scripts are available for each algorithm:
```bash
./contrib/testnet_falcon_test.sh
./contrib/testnet_dilithium2_test.sh
./contrib/testnet_raccoong_test.sh
```

These scripts automate:
- Testnet wallet generation
- PQC keypair generation (Falcon-512, Dilithium2, or Raccoon-G-44)
- tx_sighash signing
- Commitment generation
- Canonical P2SH carrier reveal carriage of PQC public key/signature
- SPV monitoring instructions

For protocol rationale/specification details, see:
- `doc/spec/bip-post-quantum-signature-commitments.mediawiki`

### Mainnet PQC Carrier Transaction Examples (Confirmed April 8, 2026)

The following real mainnet transactions demonstrate the two-transaction PQC carrier flow
with SPV node validation of Falcon-512 commitments.

#### Transaction Flow Overview

```
TX_C (Commitment Transaction) — standard P2PKH + OP_RETURN + P2SH
  Input:  DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr (funded address, secp256k1 signed)
  Output 0: Change back to DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr (P2PKH)
  Output 1: OP_RETURN 6a24 FLC1 <32-byte SHA256 commitment>
  Output 2: 1 DOGE to A6bAFnGqeKDiYk9dwkLqJSYX96ECHZ2f3q (P2SH carrier output)

TX_R (Reveal Transaction) — spends P2SH carrier with PQC payload in scriptSig
  Input:  A6bAFnGqeKDiYk9dwkLqJSYX96ECHZ2f3q (P2SH carrier from TX_C)
  Output: DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr (return funds minus fee)
```

#### Commitment Math

```
commitment = SHA256( falcon_public_key || falcon_signature )

Where:
  falcon_public_key  = 897 bytes (Falcon-512 public key)
  falcon_signature   = ~652-666 bytes (Falcon-512 signature over tx_sighash32)
  tx_sighash32       = SHA256d(serialized_tx_input) — the sighash of the spending input
```

The 32-byte commitment is embedded in TX_C's OP_RETURN output.
The full public key and signature are embedded in TX_R's scriptSig as 3 data pushes
of up to 520 bytes each (the Bitcoin/Dogecoin script push limit).

#### TX_R ScriptSig Structure (Carrier Mode)

```
scriptSig = <TAG8> <HDR8> <CHUNK0> <CHUNK1> <CHUNK2> <redeemScript>

Where:
  TAG8         = 08 464c433146554c4c   (8 bytes: "FLC1FULL" — Falcon-512 full reveal tag)
  HDR8         = 08 0100010003810612   (8 bytes: version=1, part=1/1, pk_len=897, sig_len=variable)
  CHUNK0       = 4d0802 <520 bytes>    (OP_PUSHDATA2, first 520 bytes of pk||sig)
  CHUNK1       = 4d0802 <520 bytes>    (OP_PUSHDATA2, next 520 bytes of pk||sig)
  CHUNK2       = 4d0202 <~517 bytes>   (OP_PUSHDATA2, remaining bytes of pk||sig)
  redeemScript = 06 757575757551       (6 bytes: OP_DROP OP_DROP OP_DROP OP_DROP OP_DROP OP_1)
```

#### Confirmed TX_C Example: `a9f2f84b` (Block 6156750)

```
TXID: a9f2f84b3f2dff84c4505ac680ea6932224eb69c0960d00a5ad8f49df18b4e1e
Block: 6156750 | Size: 271 bytes | Fee: 0.001 DOGE

Input:
  DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr  33.931 DOGE (standard secp256k1 P2PKH)

Outputs:
  [0] DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr  32.930 DOGE (P2PKH change)
      script: 76a9145a29227bb518c38cae5a9a195cafc56b22d7272b88ac
  [1] OP_RETURN  0 DOGE (Falcon-512 commitment)
      script: 6a24 464c4331 43b877ae18aa928ce080b472e0c16758014d7a1885c9f9ef43b148ba0a942da6
      decode: OP_RETURN OP_PUSH36 "FLC1" <32-byte commitment>
      commitment: 43b877ae18aa928ce080b472e0c16758014d7a1885c9f9ef43b148ba0a942da6
  [2] A6bAFnGqeKDiYk9dwkLqJSYX96ECHZ2f3q  1.000 DOGE (P2SH carrier)
      script: a9149b402803555511d15d81207d3e2cb3e6bc365e0e87

SPV validation log:
  [falcon-commit] Valid at height=6156750 txpos=11
    commit=43b877ae18aa928ce080b472e0c16758014d7a1885c9f9ef43b148ba0a942da6
    source=op_return_only
```

#### Confirmed TX_R Example: `c32635aa` (Block 6156750)

```
TXID: c32635aafa32abf9c89b5e366d647231c143b3fb1b925e51b51a67b6133e7924
Block: 6156750 | Size: 1675 bytes | Fee: 0.005 DOGE (299 sat/byte)

Input:
  A6bAFnGqeKDiYk9dwkLqJSYX96ECHZ2f3q  1.000 DOGE (P2SH carrier output)

  scriptSig decode:
    TAG:    464c433146554c4c  ("FLC1FULL")
    HEADER: 0100010003810612  (v1, part 1/1, pk_len=897 [0x0381], sig_len depends on chunk sizes)
    CHUNK0: 520 bytes — contains Falcon-512 public key bytes [0..519]
    CHUNK1: 520 bytes — contains pk bytes [520..896] + signature bytes [0..142]
    CHUNK2: 514 bytes — contains remaining signature bytes [143..656]
    redeemScript: 757575757551 (OP_DROP×5 OP_1)

  Extracted PQC data:
    pk_len=897 bytes, pk_prefix=091f7e11e2bbcb2329bd0c53e1544303
    sig_len=657 bytes, sig_prefix=3938a41d3ffc68a55583033a2be98c11

Output:
  [0] DDMpdcTrWnZT38tRMebbYzCSAgLSnVMqvr  0.995 DOGE (P2PKH)
      script: 76a9145a29227bb518c38cae5a9a195cafc56b22d7272b88ac

SPV validation log:
  [falcon-commit] Valid at height=6156750 txpos=12
    commit=3a83c1c63136e11862220ce97e61f83e7deea2426a79767b70aeada9781058b3
    carrier_vin=0 source=carrier_scriptsig
    pk_len=897 sig_len=657
    pk_prefix=091f7e11e2bbcb2329bd0c53e1544303
    sig_prefix=3938a41d3ffc68a55583033a2be98c11

Validation math:
  SHA256(pk[897 bytes] || sig[657 bytes]) = 3a83c1c63136e11862220ce97e61f83e7deea2426a79767b70aeada9781058b3
  This matches the commitment in the corresponding TX_C OP_RETURN at height=6156662.
```

#### SPV Node Validation Summary (All Confirmed PQC Transactions)

```
Block    TxPos  Type           Source              Commitment (first 16 hex chars)
------   -----  ----           ------              --------------------------------
6156358  8      falcon TX_C    op_return_only      0657e61928b8eb2b...
6156374  21     falcon TX_C    op_return_only      492c7dcba00e3e48...
6156388  27     falcon TX_C    op_return_only      d87439a60ba163f5...
6156389  2      falcon TX_R    carrier_scriptsig   492c7dcba00e3e48... (pk=897, sig=652)
6156399  21     falcon TX_C    op_return_only      5a6bc01cfa36880a...
6156425  5      falcon TX_R    carrier_scriptsig   d87439a60ba163f5... (pk=897, sig=660)
6156450  2      falcon TX_R    carrier_scriptsig   5a6bc01cfa36880a... (pk=897, sig=656)
6156513  26     falcon TX_C    op_return_only      818da8f9c669bc93...
6156590  6      falcon TX_C    op_return_only      94308315af523595...
6156605  4      dilithium TX_C op_return_only      752b2c664c68d89d...
6156642  13     falcon TX_C    op_return_only      09de67bc49953e88...
6156662  34     falcon TX_C    op_return_only      3a83c1c63136e118...
6156750  11     falcon TX_C    op_return_only      43b877ae18aa928c...
6156750  12     falcon TX_R    carrier_scriptsig   3a83c1c63136e118... (pk=897, sig=657)
6156760  27     falcon TX_C    op_return_only      6d320fc44e953d60...
6156770  9      falcon TX_C    op_return_only      bbadbf7a8e4b95ab...
6156781  10     falcon TX_R    carrier_scriptsig   bbadbf7a8e4b95ab... (pk=897, sig=657)

Summary: 17 total validations (12 op_return_only TX_C, 5 carrier_scriptsig TX_R, 1 dilithium2)
```

#### Block Explorer Links

- TX_C `a9f2f84b`: https://chain.so/tx/DOGE/a9f2f84b3f2dff84c4505ac680ea6932224eb69c0960d00a5ad8f49df18b4e1e
- TX_R `c32635aa`: https://chain.so/tx/DOGE/c32635aafa32abf9c89b5e366d647231c143b3fb1b925e51b51a67b6133e7924
- TX_R `3bee4f9c`: https://chain.so/tx/DOGE/3bee4f9c11c6e03ab7117e4198a272b08b61546d7da85edef9c5ec6f74dd5f55
- TX_C `30792ead`: https://chain.so/tx/DOGE/30792ead6159203b9b87f3c5ad323e9086b51fc038a8e1f8da14c1e61dcfd961
- TX_R `ff82dc5d`: https://chain.so/tx/DOGE/ff82dc5d1ba99528adc8754354c4c44149cfaf3d2e26fefd2ee7922280863813
