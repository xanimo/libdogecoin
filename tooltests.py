#!/usr/bin/env python
# Copyright (c) 2016 Jonas Schnelli
# Copyright (c) 2022 bluezr
# Copyright (c) 2022 The Dogecoin Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import sys, os
from subprocess import call

valgrind = True;
commands = []
commands.append(["-v", 0])
commands.append(["-foobar", 1])
commands.append(["-c generate_private_key", 0])
commands.append(["-c generate_private_key --testnet", 0])
commands.append(["-c generate_private_key --regtest", 0])
commands.append(["", 1])
commands.append(["-c print_keys", 1])
commands.append(["-c print_keys -p dgub8kXBZ7ymNWy2SYQeuwTf2wG8KT6asvgAFBqX4qeg4SzgiK7QvwcXQ9StrWCjFeWovX1tVrEikxcci2XQsZSbkgnispVsfgYpEBdLoPTv7W9", 0])
commands.append(["-c print_keys -p dgpv51eADS3spNJh9gkVshqgv5iXrtix3oeSxb4JujFhGKwgAFziXB4kkr3FHH5Lcb9oF1hogYNeuVrP7JcE6wmoVgqwC21s8hQrTVMKN895etg", 0])
commands.append(["-c print_keys -p dgpv51eADS3spNJh9gkVshqgv5iXrtix3oeSxb4JujFhGKwgAFziXB4kkr3FHH5Lcb9oF1hogYNeuVrP7JcE6wmoVgqwC21s8hQrTVMKN895etg --testnet", 1])
commands.append(["-c generate_public_key -p QQR1EyvwHNuo1aqBmRinDbsZ93WrVzfdK18Z7G8P9tEmsUQE185k", 0]) #successfull WIF to pub
commands.append(["-c generate_public_key", 1]) #missing required argument
commands.append(["-c generate_public_key -p QQR1EyvwHNuo1aqBmRinDbsZ93WrVzfdK18", 1]) #invalid WIF key
commands.append(["-c p2pkh -p 024fc3b764ce26da9b06f36c68503309d3e5baf5c4d6754e1deac1a53a81a7700c", 1])
commands.append(["-c p2pkh -k 024fc3b764ce26da9b06f36c68503309d3e5baf5c4d6754e1deac1a53a81a7700c", 0])
commands.append(["-c bip32_extended_master_key", 0])
commands.append(["-c derive_child_keys -p dgub8kXBZ7ymNWy2SHeQsQZMqDyXBEGquxHY8JNQ5ir4DNgB79VveeGMGLDbAgpG2ma3kaRGhpozZW5pAPSPrLJxsEAkLaTsGfcHgEMiXEtTCL2 -m m/100h/10h/100/10", 1]) #hardened keypath with pubkey
commands.append(["-c derive_child_keys -p dgpv51eADS3spNJh9RzFqAwPiNRvifuD5qFpqhbBvcT5RFdAZ6PEEsiad2owbSP2S9rUGs3RXw9q7hr6BPyX1hhvgQMVPL45nP2v3hx5GoPttaG -m m/100h/10h/100/10", 0])
commands.append(["-c derive_child_keys -p dgpv51eADS3spNJh9RzFqAwPiNRvifuD5qFpqhbBvcT5RFdAZ6PEEsiad2owbSP2S9rUGs3RXw9q7hr6BPyX1hhvgQMVPL45nP2v3hx5GoPttaG -m n/100h/10h/100/10", 1]) #wrong keypath prefix
commands.append(["-c derive_child_keys -p dgub8kXBZ7ymNWy2SHeQsQZMqDyXBEGquxHY8JNQ5ir4DNgB79VveeGMGLDbAgpG2ma3kaRGhpozZW5pAPSPrLJxsEAkLaTsGfcHgEMiXEtTCL2 -m m/100/10/100/10", 0])
commands.append(["-c derive_child_keys", 1]) #missing key
commands.append(["-c derive_child_keys -p dgub8kXBZ7ymNWy2SHeQsQZMqDyXBEGquxHY8JNQ5ir4DNgB79VveeGMGLDbAgpG2ma3kaRGhpozZW5pAPSPrLJxsEAkLaTsGfcHgEMiXEtTCL2", 1]) #missing keypath

baseCommand = "./such"
if valgrind == True:
    baseCommand = "valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes  "+baseCommand

errored = False
for cmd in commands:
    retcode = call(baseCommand+" "+cmd[0], shell=True)
    if retcode != cmd[1]:
        print("ERROR during "+cmd[0])
        sys.exit(os.EX_DATAERR)

sys.exit(os.EX_OK)