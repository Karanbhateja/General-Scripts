# Folder Integrity Checker

A simple Python tool to **track file integrity** by hashing all files in a folder and detecting **new, changed, or deleted files** across runs.

Ideal for backups, audits, configuration folders, and integrity monitoring.

---

## Features

- Recursive folder scanning
- Detects **changed / new / deleted** files
- Supports `md5`, `sha1`, `sha256`, `sha512`
- Remembers selected hash algorithm
- Interactive mode if folder not provided
- Stores hash database inside the target folder
- Excludes its own hash file automatically
- No external dependencies

---

## Requirements

- Python **3.10+**
- Standard library only

---

## Usage

### How to Use (Examples)

```bash
# First run → will ask for folder + hash algo
python script.py

# Reuse saved algo + provide folder
python script.py "C:\Google Drive\ISO27001"

# Force a different algorithm (and it will be saved for next runs)
python script.py --hash-algo sha512

# Custom hash file
python script.py --hash-file iso_sha256.json

```
---

## Hash Algorithms

Available algorithms:
- `md5`
- `sha1`
- `sha256` *(default & recommended)*
- `sha512`

> ⚠️ MD5 and SHA1 are included for compatibility only.  
> Use **SHA256 or SHA512** for secure integrity checks.

---

## Hash Database

- Stored as a JSON file inside the scanned folder
- Contains file hashes, timestamps, and metadata
- Automatically reused on subsequent runs
- The hash file itself is excluded from scanning

---

## Behavior Notes

- The tool **never modifies or deletes files**
- Hash database updates require user confirmation
- File read errors are reported but do not stop execution

---

## License

MIT License
