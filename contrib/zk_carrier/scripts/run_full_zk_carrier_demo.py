#!/usr/bin/env python3
"""Python entry point for the ZK carrier end-to-end demo.

Wraps ``contrib/zk_carrier/scripts/run_full_zk_carrier_demo.sh`` so the
same flow is importable from tests or from a wallet/UI bridge.  All
real work happens in the shell script — this file exists so::

    from contrib.zk_carrier.scripts.run_full_zk_carrier_demo import run_demo

works exactly the same as the shell entry point.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Mapping, Optional

SCRIPT_PATH = Path(__file__).resolve().with_suffix(".sh")


def run_demo(args: Iterable[str] = (),
             env: Optional[Mapping[str, str]] = None) -> int:
    """Run the full demo.  Returns the shell script's exit code.

    Args:
        args: Extra CLI flags to pass through (e.g. ``["--testnet",
              "--skip-broadcast"]``).  See the shell script's ``--help`` for
              the supported flags.
        env: Optional environment overrides; merged on top of ``os.environ``.
              Recognised variables include ``ZK_CARRIER_WIF``,
              ``FUNDED_UTXO_TXID``, ``RPC_URL``, ``TX_R_HEX`` etc. — see
              the shell script header.
    """
    if not SCRIPT_PATH.is_file():
        raise FileNotFoundError(f"{SCRIPT_PATH} not found")
    final_env = dict(os.environ)
    if env:
        final_env.update(env)
    cmd = ["bash", str(SCRIPT_PATH), *args]
    print("+ " + " ".join(shlex.quote(c) for c in cmd), file=sys.stderr)
    return subprocess.call(cmd, env=final_env)


def main(argv: Optional[list[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    return run_demo(argv)


if __name__ == "__main__":
    sys.exit(main())
