#!/usr/bin/env python3
"""
Folder Integrity Checker
------------------------
- Computes file hashes recursively in a folder
- Stores hashes inside the folder (excluded from scanning)
- Detects new/changed/deleted files
- Remembers chosen hash algorithm
- Interactive folder selection if not provided
"""

import os
import json
import hashlib
import argparse
import time
from pathlib import Path

# ────────────────────────────────────────────────
#  ANSI Colors & Symbols
# ────────────────────────────────────────────────
class Style:
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RED     = '\033[31m'
    GREEN   = '\033[32m'
    YELLOW  = '\033[33m'
    BLUE    = '\033[34m'
    CYAN    = '\033[36m'
    WHITE   = '\033[97m'

S = {
    'ok':    f"{Style.GREEN}✓{Style.RESET}",
    'fail':  f"{Style.RED}✗{Style.RESET}",
    'warn':  f"{Style.YELLOW}⚠{Style.RESET}",
    'info':  f"{Style.BLUE}i{Style.RESET}",
    'arrow': f"{Style.CYAN}→{Style.RESET}",
    'star':  f"{Style.YELLOW}★{Style.RESET}",
}

# ────────────────────────────────────────────────
#  Supported hash algorithms
# ────────────────────────────────────────────────
HASH_ALGOS = {
    'md5':    hashlib.md5,
    'sha1':   hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
}

DEFAULT_HASH_FILE = "integrity_hashes.json"


def get_hasher(algo: str):
    if algo not in HASH_ALGOS:
        raise ValueError(f"Unsupported hash algorithm: {algo}")
    return HASH_ALGOS[algo]()


def compute_hash(filepath: Path, algo: str) -> str | None:
    hasher = get_hasher(algo)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"  {S['warn']} Could not read {filepath.name}  →  {e}")
        return None


def scan_folder(root_dir: Path, algo: str) -> dict[str, dict]:
    """Returns: {rel_path: {'hash': str, 'mtime': float}}"""
    files_data = {}
    skipped = 0

    for path in root_dir.rglob("*"):
        if not path.is_file():
            continue

        rel = str(path.relative_to(root_dir))

        # Skip our own hash file (and possible variants)
        if rel == DEFAULT_HASH_FILE or rel.endswith((".hashes.json", ".integrity.json")):
            continue

        try:
            mtime = path.stat().st_mtime
            h = compute_hash(path, algo)
            if h:
                files_data[rel] = {"hash": h, "mtime": mtime}
        except Exception as e:
            print(f"  {S['warn']} Skipped {rel}  →  {e}")
            skipped += 1

    if skipped:
        print(f"  {S['info']} {skipped} file(s) skipped due to errors")

    return files_data


def choose_algorithm(default: str = "sha256") -> str:
    print(f"\n  {S['info']} Available algorithms: {', '.join(HASH_ALGOS)}")
    print(  "  Recommended → sha256\n")

    while True:
        ans = input(f"  Select algorithm {Style.DIM}(Enter = {default}){Style.RESET}: ").strip().lower()
        if not ans:
            return default
        if ans in HASH_ALGOS:
            return ans
        print(f"  {S['warn']} Invalid choice. Try again.")


def print_header():
    print(f"\n{Style.CYAN}{Style.BOLD}══ Folder Integrity Checker ════════════════════════════════{Style.RESET}")


def print_section(title: str):
    print(f"\n{Style.CYAN}┌─ {title} ─{'─' * (48 - len(title))}{Style.RESET}")


def main(folder: str | None, custom_hash_file: str | None, force_algo: str | None):
    print_header()

    # ── Resolve folder ───────────────────────────────────────
    if not folder:
        print(f"  {S['info']} No folder path provided → interactive mode\n")
        while True:
            inp = input(f"  Folder path: ").strip()
            if not inp:
                continue
            p = Path(os.path.expanduser(inp)).resolve()
            if p.is_dir():
                folder_path = p
                print(f"  {S['ok']} Using: {folder_path}\n")
                break
            print(f"  {S['fail']} Directory not found. Try again.")
    else:
        folder_path = Path(os.path.expanduser(folder)).resolve()
        if not folder_path.is_dir():
            print(f"  {S['fail']} Not a directory: {folder_path}")
            return

    # ── Hash file location ───────────────────────────────────
    if custom_hash_file:
        if os.path.isabs(custom_hash_file):
            hash_path = Path(custom_hash_file)
        else:
            hash_path = folder_path / custom_hash_file
    else:
        hash_path = folder_path / DEFAULT_HASH_FILE

    print(f"  {S['arrow']} Target folder :  {folder_path}")
    print(f"  {S['arrow']} Hash database :  {hash_path}\n")

    # ── Load previous data ───────────────────────────────────
    previous = {}
    current_algo = force_algo
    meta = {}

    if hash_path.is_file():
        try:
            with open(hash_path, encoding="utf-8") as f:
                data = json.load(f)
                previous = data.get("files", {})
                meta = data.get("__meta__", {})
                saved_algo = meta.get("algo")
                if saved_algo and not force_algo:
                    current_algo = saved_algo
                    print(f"  {S['info']} Using saved algorithm: {Style.BOLD}{current_algo}{Style.RESET}")
        except Exception as e:
            print(f"  {S['warn']} Could not read previous hash file → starting fresh ({e})")

    if not current_algo:
        current_algo = choose_algorithm()

    print(f"  {S['arrow']} Hash algorithm:  {Style.BOLD}{current_algo}{Style.RESET}\n")

    # ── Scan current state ───────────────────────────────────
    print_section("Scanning")
    current = scan_folder(folder_path, current_algo)
    print(f"  {S['ok']} Found {len(current):,} files\n")

    # ── Compare ──────────────────────────────────────────────
    print_section("Comparison")

    changed = []
    new     = []
    deleted = []

    for rel, info in current.items():
        if rel in previous:
            if info["hash"] != previous[rel]["hash"]:
                changed.append(rel)
        else:
            new.append(rel)

    for rel in previous:
        if rel not in current:
            deleted.append(rel)

    any_change = bool(changed or new or deleted)

    if changed:
        print(f"  {Style.YELLOW}Changed files ({len(changed)}):{Style.RESET}")
        for p in sorted(changed):
            print(f"      {p}")
        print()

    if new:
        print(f"  {Style.GREEN}New files ({len(new)}):{Style.RESET}")
        for p in sorted(new):
            print(f"      {p}")
        print()

    if deleted:
        print(f"  {Style.RED}Deleted files ({len(deleted)}):{Style.RESET}")
        for p in sorted(deleted):
            print(f"      {p}")
        print()

    if not any_change:
        print(f"  {S['ok']} {Style.GREEN}No changes detected — integrity verified{Style.RESET}\n")

    # ── Offer update ─────────────────────────────────────────
    if any_change:
        print(f"  {S['arrow']} Would you like to update the hash database?")
        ans = input(f"  {Style.DIM}(y/N){Style.RESET} ").strip().lower()
        if ans in ('y', 'yes'):
            output = {
                "__meta__": {
                    "algo": current_algo,
                    "folder": str(folder_path),
                    "last_updated": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                    "file_count": len(current),
                },
                "files": current
            }
            try:
                with open(hash_path, "w", encoding="utf-8") as f:
                    json.dump(output, f, indent=2, sort_keys=True)
                print(f"\n  {S['ok']} {Style.GREEN}Hash database updated successfully{Style.RESET}")
                print(f"     Location: {hash_path}\n")
            except Exception as e:
                print(f"  {S['fail']} Could not save hash file: {e}\n")
        else:
            print(f"  {S['warn']} Update skipped.\n")
    else:
        print(f"  {S['info']} Hash database is already up-to-date.\n")

    print(f"{Style.CYAN}═══════════════════════════════════════════════════════════{Style.RESET}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Folder integrity checker with change detection",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("folder", nargs="?", default=None,
                        help="Path to folder (optional – will prompt if omitted)")
    parser.add_argument("--hash-file", metavar="NAME", default=None,
                        help="Custom name for the hash file inside the folder")
    parser.add_argument("--hash-algo", choices=list(HASH_ALGOS.keys()),
                        help="Force specific hash algorithm (overrides saved value)")

    args = parser.parse_args()
    main(args.folder, args.hash_file, args.hash_algo)
