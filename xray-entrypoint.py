#!/usr/bin/env python3
"""Materialize TXT endpoints, then exec Xray with the runtime config."""

import argparse
import json
import os
from pathlib import Path

from txt_endpoints import materialize_config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--xray", required=True)
    args = parser.parse_args()

    source = json.loads(Path(args.source).read_text())
    runtime, resolved = materialize_config(source, args.cache)
    target = Path(args.runtime)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(json.dumps(runtime, ensure_ascii=False, indent=2) + "\n")
    os.replace(temp, target)
    for item in resolved:
        print(
            "TXT endpoint: {tag} {host} -> {address}:{port}".format(**item),
            flush=True,
        )
    os.execv(args.xray, [args.xray, "run", "-config", args.runtime])


if __name__ == "__main__":
    main()
