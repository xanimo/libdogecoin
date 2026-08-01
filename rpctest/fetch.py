#!/usr/bin/python3
import os
import sys
import requests, zipfile
from io import BytesIO
import hashlib
import subprocess
import tarfile
import glob
import shutil
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--host", help="provide target host triplet")
args = parser.parse_args()
host = ""
if args.host:
    host = args.host
    os.environ['host'] = host
elif os.environ['host']:
    host = os.environ['host']

assert host in ("arm-linux-gnueabihf",
                "aarch64-linux-gnu",
                "x86_64-linux-gnu",
                "x86_64-apple-darwin14",
                "x86_64-w64-mingw32",
                "i686-w64-mingw32",
                "i686-pc-linux-gnu",), "Invalid architecture."

hash = ""
if host == "arm-linux-gnueabihf":
    ext = ".tar.gz"
    hash = "311fe8aee346d3f9a00c0a8ac594224ca3bfa297fec8a5fae20bb70f28961421  dogecoin-1.14.6-arm-linux-gnueabihf.tar.gz"
elif host == "aarch64-linux-gnu":
    ext = ".tar.gz"
    hash = "6928c895a20d0bcb6d5c7dcec753d35c884a471aaf8ad4242a89a96acb4f2985  dogecoin-1.14.6-aarch64-linux-gnu.tar.gz"
elif host == "x86_64-w64-mingw32":
    ext = ".zip"
    hash = "709490ac8464b015266884831a2b5b594efc8b2c17a7e6b85255058cbee049de  dogecoin-1.14.6-win64.zip"
elif host == "i686-w64-mingw32":
    ext = ".zip"
    hash = "c919fdc966764ec554273791699426448eedd8d305e76284e4f1cd1d5f0b5a7a  dogecoin-1.14.6-win32.zip"
elif host == "x86_64-apple-darwin14":
    ext = ".tar.gz"
    hash = "bf6123a91ba2829e03dc7c48865971dd615b78249f6ee41a4e796f942bd93869  dogecoin-1.14.6-osx-unsigned.dmg"
elif host == "x86_64-linux-gnu":
    ext = ".tar.gz"
    hash = "4f227117b411a7c98622c970986e27bcfc3f547a72bef65e7d9e82989175d4f8  dogecoin-1.14.6-x86_64-linux-gnu.tar.gz"
elif host == "i686-pc-linux-gnu":
    ext = ".tar.gz"
    hash = "b8e1846a0979f369042dcf14435dfcea704b1456e34bc9657f0829d9eac0d3b0  dogecoin-1.14.6-i686-pc-linux-gnu.tar.gz"

print('Downloading started')
file = "dogecoin-1.14.6-" + host
base = "https://github.com/dogecoin/dogecoin/releases/download/v1.14.6/"
url = base + file + ext
sha256sums = base + "SHA256SUMS.asc"

req_sha = requests.get(sha256sums)
checksum = sha256sums.split('/')[-1]
with open(checksum,'wb') as output_checksum:
    output_checksum.write(req_sha.content)
print("\033[1;32m> Downloading SHA256SUMS.asc Completed\033[0m")

req = requests.get(url)
filename = url.split('/')[-1]
with open(filename,'wb') as output_file:
    output_file.write(req.content)
print("\033[1;32m> Downloading " + filename + " Completed\033[0m")

sha256_hash = hashlib.sha256()
with open(filename,"rb") as f:
    for byte_block in iter(lambda: f.read(4096),b""):
        sha256_hash.update(byte_block)

with open("SHA256SUMS.asc", "r") as get_hash:
    for line in get_hash.readlines():
        if filename and hash in line:
            if line.strip() == hash:
                if sha256_hash.hexdigest() != line.split()[0]:
                    print("\033[31m> checksums don't match!\033[0m")
                    exit(1)
                else:
                    print("\033[1;32m> checksums match!\033[0m")
            else:
                print("\033[31m> no valid checksum found!\033[0m")
                exit(1)

if ext == ".zip":
    zipfile= zipfile.ZipFile(BytesIO(req.content))
    zipfile.extractall(os.getcwd())
else:
    with tarfile.open(fileobj=BytesIO(req.content), mode='r:gz') as tar:
        tar.extractall(os.getcwd())
        tar.close()

deps_path = ["dogecoind"]
for f in deps_path:
    src = "dogecoin-1.14.6/bin/" + f
    src_path = os.path.join(os.getcwd(), src)
    if os.path.isdir('/usr/local/bin'):
        dst_path = os.path.join('/usr/local/bin', f)
        shutil.move(src_path, dst_path)

# Bound the SPV test. It drives a real spvnode against a regtest dogecoind, so a
# client-side stall (waiting on a peer for data it will never send) would
# otherwise hang here until the CI job hits its own hour-long limit and is
# killed with no useful output. Fail fast and loudly instead.
SPVTOOL_TIMEOUT = int(os.environ.get("SPVTOOL_TIMEOUT", "900"))
try:
    completed = subprocess.run(
        [os.path.join(os.getcwd(), "rpctest/spvtool.py")],
        timeout=SPVTOOL_TIMEOUT,
    )
except subprocess.TimeoutExpired:
    print("\033[31m> spvtool.py exceeded %ds and was killed - treating as failure.\033[0m"
          % SPVTOOL_TIMEOUT, file=sys.stderr)
    print("\033[31m> This usually means spvnode never reached 'Sync completed' "
          "and is waiting on a peer.\033[0m", file=sys.stderr)
    sys.exit(1)

if completed.returncode != 0:
    print("\033[31m> spvtool.py failed with exit code %d\033[0m" % completed.returncode,
          file=sys.stderr)
    sys.exit(completed.returncode)

rmlist = ['./dogecoin-*', '*.dmg', '*.tar.gz', '*.zip', '*.asc']
for path in rmlist:
    for name in glob.glob(path):
        if os.path.isdir(name):
            try:
                shutil.rmtree(name)
            except OSError as e:
                print("Error: %s : %s" % (name, e.strerror))
        if os.path.isfile(name):
            try:
                os.remove(name)
            except OSError as e:
                print("Error: %s : %s" % (name, e.strerror))
