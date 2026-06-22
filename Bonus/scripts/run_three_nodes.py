from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

KEYS = [
    ROOT / "keys" / "node0.pem",
    ROOT / "keys" / "node1.pem",
    ROOT / "keys" / "node2.pem",
]


def main() -> None:
    processes: list[subprocess.Popen] = []

    for i, key in enumerate(KEYS):
        if not key.exists():
            raise FileNotFoundError(f"Missing key file: {key}")

        cmd = [
            "uv",
            "run",
            "python",
            "-m",
            "src.main",
            "--key",
            str(key),
        ]

        # Register the blockchain using the first node.
        if i == 0:
            cmd.append("--register")

        print(f"Starting node {i}: {' '.join(cmd)}")

        processes.append(
            subprocess.Popen(
                cmd,
                cwd=ROOT,
            )
        )

    try:
        for process in processes:
            process.wait()
    except KeyboardInterrupt:
        print("\nStopping nodes...")

        for process in processes:
            process.terminate()

        for process in processes:
            process.wait()


if __name__ == "__main__":
    main()