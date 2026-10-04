"""Inspect artifact presence without importing the application or loading models."""

import argparse
import json
from pathlib import Path


def inspect(root):
    """Return named presence checks; never deserialize pickle or model weights."""
    checkpoint = root / "new_fine_tuned_model"
    checks = [
        (name, (root / name).is_file())
        for name in ("access_control_rules.md", "rules_index.faiss", "rules_chunks.pkl")
    ]
    checks.append(("checkpoint config.json", (checkpoint / "config.json").is_file()))
    weights = any((checkpoint / name).is_file() for name in (
        "model.safetensors", "pytorch_model.bin",
    ))
    for name in ("model.safetensors.index.json", "pytorch_model.bin.index.json"):
        index = checkpoint / name
        if index.is_file():
            try:
                mapping = json.loads(index.read_text(encoding="utf-8")).get("weight_map", {})
                shards = list(mapping.values()) if isinstance(mapping, dict) else []
                complete = bool(shards) and all(
                    isinstance(shard, str)
                    and Path(shard).name == shard
                    and (checkpoint / shard).is_file()
                    for shard in shards
                )
                weights = weights or complete
            except (OSError, ValueError, AttributeError):
                pass
    checks.append(("checkpoint weights (including indexed shards)", weights))
    checks.append(("checkpoint tokenizer assets", any(
        (checkpoint / name).is_file() for name in ("tokenizer.json", "spiece.model")
    )))
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="Repository root (defaults to this script's repository)")
    args = parser.parse_args()
    checks = inspect(args.root)
    for name, present in checks:
        print(f"{'PRESENT' if present else 'MISSING'}  {name}")
    print("\nPresence only: contents, compatibility, dependencies, configuration, and privacy controls are not validated.")
    print("No model, pickle, application module, database, or external service was loaded.")
    return 0 if all(present for _, present in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
