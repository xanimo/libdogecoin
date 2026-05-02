#!/usr/bin/env python3
"""ZK carrier witness/proof helper.

Drives ``snarkjs groth16 fullprove`` for the range-proof circuit (or any
other circuit you point it at), then encodes the resulting (public_inputs,
proof) pair into the canonical ZK carrier payload that libdogecoin's
``such -c zk_add_commit_and_carrier_tx`` consumes.

This is the **only** supported way to produce ZK carrier payloads from
libdogecoin's perspective — proving never runs inside the C library
(see ``include/dogecoin/zk_carrier.h`` and ``src/zk_carrier/zk_groth16.c``).

Usage::

    python3 contrib/zk_carrier/witness_helper.py \\
        --wasm  contrib/zk_carrier/circuits/build/range_proof_js/range_proof.wasm \\
        --zkey  contrib/zk_carrier/circuits/build/range_proof.zkey \\
        --vkey  contrib/zk_carrier/circuits/build/verification_key.json \\
        --low   0 --high 1000000 --amount 42000 \\
        --circuit-id 1 \\
        --out-payload payload.hex

Output: ``payload.hex`` is the ASCII-hex of the canonical ZKP1 payload.
Pass it via ``-s`` to ``such -c zk_add_commit_and_carrier_tx``.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

ZK_MAGIC = b"ZKP1"
MODE_GROTH16 = 0
MODE_PLONK = 1
PROOF_SYSTEMS = {"groth16": MODE_GROTH16, "plonk": MODE_PLONK}


def _require(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        sys.exit(f"error: required tool '{tool}' not found on PATH")
    return p


def _run(cmd: Sequence[str]) -> None:
    print("+", " ".join(cmd), file=sys.stderr)
    subprocess.run(list(cmd), check=True)


def encode_payload(mode: int, circuit_id: int,
                   public_inputs: bytes, proof: bytes,
                   vk: bytes | None = None) -> bytes:
    """Encode the canonical ZKP1 payload (matches dogecoin_zk_encode_payload).

    When ``vk`` is provided and non-empty the payload is emitted as v1
    (vk-included): the version byte at offset 5 is 0x01 and the trailing
    ``PROOF_LEN4 || PROOF`` block is followed by ``VK_LEN4 || VK`` so the
    on-chain reveal alone is sufficient for full proof validation (no
    out-of-band channel needed).  When ``vk`` is None / empty the payload is
    emitted as v0, matching the earlier on-chain pairs (Pair A / Pair B / Pair P)
    documented in the BIP.
    """
    if mode < 0 or mode > 0xFF:
        raise ValueError("mode out of range")
    if len(public_inputs) > 0xFFFF:
        raise ValueError("public_inputs too large (>65535 bytes)")
    if len(proof) > 0x02000000:
        raise ValueError("proof too large (>32 MiB)")
    vk = vk or b""
    if len(vk) > 0x02000000:
        raise ValueError("vk too large (>32 MiB)")
    version = 0x01 if vk else 0x00
    out = bytearray()
    out += ZK_MAGIC
    out += bytes([mode, version])
    out += struct.pack(">I", circuit_id & 0xFFFFFFFF)
    out += struct.pack(">H", len(public_inputs))
    out += public_inputs
    out += struct.pack(">I", len(proof))
    out += proof
    if vk:
        out += struct.pack(">I", len(vk))
        out += vk
    return bytes(out)


def run_fullprove(snarkjs: str, system: str, wasm: Path, zkey: Path,
                  input_path: Path, proof_path: Path, public_path: Path) -> None:
    _run([snarkjs, system, "fullprove", str(input_path), str(wasm),
          str(zkey), str(proof_path), str(public_path)])


def run_verify(snarkjs: str, system: str, vkey: Path,
               public_path: Path, proof_path: Path) -> bool:
    res = subprocess.run([snarkjs, system, "verify", str(vkey),
                          str(public_path), str(proof_path)])
    return res.returncode == 0


def build_payload(args: argparse.Namespace) -> bytes:
    snarkjs = _require("snarkjs")
    wasm = Path(args.wasm).resolve()
    zkey = Path(args.zkey).resolve()
    if not wasm.is_file():
        sys.exit(f"error: wasm file not found: {wasm}")
    if not zkey.is_file():
        sys.exit(f"error: zkey file not found: {zkey}")

    system = args.proof_system
    if system not in PROOF_SYSTEMS:
        sys.exit(f"error: unsupported --proof-system {system!r} (choose: {', '.join(PROOF_SYSTEMS)})")
    mode = PROOF_SYSTEMS[system]

    with tempfile.TemporaryDirectory(prefix="zkc_") as td:
        td_p = Path(td)
        input_path = td_p / "input.json"
        proof_path = td_p / "proof.json"
        public_path = td_p / "public.json"
        # Range-proof witness format (matches range_proof.circom).
        # If you wire a different circuit, override --input-json with the
        # exact JSON that circuit expects.
        #
        # The 4th input `tx_binding` is the 32-byte SHA256d sighash of the
        # funding (base) transaction — same value the PQC carrier signs over
        # — interpreted big-endian as a BN254 field element after zeroing
        # the top byte (see dogecoin_zk_compute_tx_base_sighash).  The
        # operator passes the 32-byte hex through --tx-binding-hex; passing
        # an all-zero binding (--tx-binding-hex 00*64) reproduces the
        # historical, replay-vulnerable demos and is rejected by SPV when
        # `[zk-commit] tx_binding mismatch` is enforced.
        tx_binding_hex = (args.tx_binding_hex or "00" * 32).lower()
        if len(tx_binding_hex) != 64 or any(c not in "0123456789abcdef" for c in tx_binding_hex):
            sys.exit("error: --tx-binding-hex must be 64 hex chars (32 bytes)")
        tx_binding_bytes = bytes.fromhex(tx_binding_hex)
        # Mirror the C-side "zero top byte" rule so the field-element
        # interpretation is unambiguous on BN254.
        tx_binding_bytes = b"\x00" + tx_binding_bytes[1:]
        tx_binding_field = int.from_bytes(tx_binding_bytes, "big")
        if args.input_json:
            input_path.write_text(Path(args.input_json).read_text())
        else:
            input_path.write_text(json.dumps({
                "low": str(args.low),
                "high": str(args.high),
                "amount": str(args.amount),
                "tx_binding": str(tx_binding_field),
            }))

        run_fullprove(snarkjs, system, wasm, zkey, input_path, proof_path, public_path)

        if args.vkey:
            if not run_verify(snarkjs, system, Path(args.vkey).resolve(),
                              public_path, proof_path):
                sys.exit(f"error: snarkjs {system} verify failed — refusing to emit payload")

        # snarkjs writes JSON; the ZKP1 payload carries it verbatim so
        # that off-box verification ('snarkjs <system> verify') and on-box
        # verification (rapidsnark, when linked) can both consume it.
        public_bytes = public_path.read_bytes()
        proof_bytes = proof_path.read_bytes()
        # When --vkey is supplied, embed the verification key bytes verbatim
        # so the on-chain reveal is fully self-contained: a verifier with no
        # access to the original vkey file can still reassemble the ZKP1
        # payload from TX_R, extract the embedded vk, and re-run
        # `snarkjs <system> verify` end-to-end.  This is the canonical
        # "everything for full validation is in the Reveal" mode (ZKP1 v1).
        # Operators may opt out via --no-embed-vk to reproduce the historical
        # v0 wire format that ships in Pair A / Pair B / Pair P on mainnet.
        vk_bytes = b""
        if args.vkey and not args.no_embed_vk:
            vk_path = Path(args.vkey).resolve()
            if vk_path.is_file():
                vk_bytes = vk_path.read_bytes()
            else:
                sys.exit(f"error: --vkey {vk_path} not found (cannot embed for v1 reveal)")

        # Persist the raw snarkjs proof.json / public.json next to the
        # caller's --out-payload (when --save-proof/--save-public are
        # provided) so the post-spvnode external verifier
        # (`snarkjs <system> verify`) in broadcast_set.sh can be invoked
        # end-to-end against the very same artefacts that were embedded
        # in the on-chain ZKP1 payload.
        if args.save_proof:
            Path(args.save_proof).write_bytes(proof_bytes)
        if args.save_public:
            Path(args.save_public).write_bytes(public_bytes)

    return encode_payload(mode, args.circuit_id, public_bytes, proof_bytes,
                          vk=vk_bytes if vk_bytes else None)


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--wasm", required=True, help="path to circuit .wasm")
    p.add_argument("--zkey", required=True, help="path to circuit .zkey (Groth16 proving key)")
    p.add_argument("--vkey", help="path to verification_key.json — when present "
                                  "the vk bytes are EMBEDDED in the ZKP1 reveal "
                                  "(v1 wire format) so the on-chain reveal is "
                                  "fully self-contained for proof validation; "
                                  "additionally used as a sanity-check vkey for "
                                  "snarkjs verify before emitting the payload")
    p.add_argument("--no-embed-vk", action="store_true",
                   help="produce a v0 ZKP1 payload (no embedded vk) even when "
                        "--vkey is supplied — used for reproducing pre-v1 "
                        "on-chain pairs and round-tripping legacy fixtures")
    p.add_argument("--circuit-id", type=lambda x: int(x, 0), default=1,
                   help="application-defined 32-bit circuit identifier (default: 1)")
    p.add_argument("--low", type=int, help="public lower bound (range proof)")
    p.add_argument("--high", type=int, help="public upper bound (range proof)")
    p.add_argument("--amount", type=int, help="private witness amount (range proof)")
    p.add_argument("--tx-binding-hex",
                   help="32-byte hex SHA256d sighash of the funding (base) tx — "
                        "the prover commits to this value as the `tx_binding` "
                        "public input, mirroring how the PQC carrier signs over "
                        "the same tx_base sighash; defaults to all-zeros for "
                        "replay-vulnerable legacy testing")
    p.add_argument("--input-json", help="optional path to a circuit-specific input.json "
                                        "(overrides --low/--high/--amount)")
    p.add_argument("--proof-system", default="groth16",
                   choices=sorted(PROOF_SYSTEMS.keys()),
                   help="proving system used by snarkjs fullprove/verify "
                        "(default: groth16, also: plonk → ZKP1 mode byte 1)")
    p.add_argument("--save-proof", help="optional path to copy the raw snarkjs proof.json "
                                        "(used by broadcast_set.sh's post-spvnode "
                                        "external verifier)")
    p.add_argument("--save-public", help="optional path to copy the raw snarkjs public.json "
                                         "(used by broadcast_set.sh's post-spvnode "
                                         "external verifier)")
    p.add_argument("--out-payload", required=True,
                   help="where to write the hex-encoded ZKP1 payload")
    args = p.parse_args(argv)

    if not args.input_json and (args.low is None or args.high is None or args.amount is None):
        p.error("either --input-json or --low/--high/--amount must be provided")

    payload = build_payload(args)
    Path(args.out_payload).write_text(payload.hex())
    # Distinguish v0 vs v1 in the operator log so the demo scripts can
    # advertise which wire format they actually committed.
    version = payload[5] if len(payload) > 5 else 0
    print(f"wrote {len(payload)}-byte ZKP1 payload (v{version}) to {args.out_payload}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
