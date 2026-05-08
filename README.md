A command-line tool for mounting encrypted filesystems using passwords stored in **KeePass**. Built with **Typer**, **Pydantic**, and **Python 3.10+**.

## Overview

This is a utility package that simplifies mounting encrypted filesystems by automating password retrieval from KeePass databases. It demonstrates:

- Modern Python packaging with `pyproject.toml`
- CLI development with **Typer**
- Type hints and static type checking with **mypy**
- Code linting with **ruff**
- Testing with **pytest**
- Dependency management with **uv**

Supports multiple encryption types including **gocryptfs** and **cryfs** with automatic detection.

## Installation

### Prerequisites

- Python 3.10 or higher
- [uv](https://github.com/astral-sh/uv) package manager
- A KeePass database file (`.kdbx`)

### Setup

Clone the repository and install with uv:

```bash
git clone https://github.com/AlexAndrewsAI/mount-encrypted-filesystem.git
cd mount-encrypted-filesystem  
uv sync
```

## Usage

### Passwords
- Example keepass database: `tests/enc.kdbx`, password `123`
- Example gocryptfs vault: `tests/gocryptfs`, password `g1`
- Example cryfs vault: `tests/cryfs`, password `c1`

### Mount an Encrypted Filesystem

```bash
mount-encfs tests/gocryptfs tests/mnt \
  --database tests/enc.kdbx
```

You'll be prompted for your KeePass password.

### Optional Arguments

- **`--enctype, -e`**: Specify encryption type (`gocryptfs` or `cryfs`). Auto-detected if omitted.
- **`--title, -t`**: Match a specific title in KeePass entries (defaults to encryption type).

### Examples

```bash
# Auto-detect encryption type, prompt for password
mount-encfs tests/gocryptfs tests/mnt --database tests/enc.kdbx

# Specify encryption type and password
mount-encfs tests/gocryptfs tests/mnt \
  --database tests/enc.kdbx \
  --enctype gocryptfs

# Match specific KeePass entry by title
mount-encfs tests/gocryptfs tests/mnt \
  --database tests/enc.kdbx \
  --title "Work Vault"
```

### Get Help

```bash
mount-encfs --help
```

## Development

### Install Dev Environment

```bash
uv sync
```

This installs all dependencies and development tools (pytest, ruff, mypy).

### Run Tests

```bash
# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -v

# Show print statements during tests
uv run pytest -s
```

### Code Quality

```bash
# Lint code
uv run ruff check mount_encrypted_filesystem tests

# Fix linting issues automatically
uv run ruff format mount_encrypted_filesystem tests

# Type check
uv run mypy mount_encrypted_filesystem
```

## Project Structure

```
mount-encrypted-filesystem/
├── .gitignore
├── pyproject.toml
├── README.md
├── mount_encrypted_filesystem/     
│   ├── __init__.py
│   ├── cli.py
│   └── mount.py
└── tests/
    ├── __init__.py
    └── test_mount.py
```

## Features

- **KeePass Integration**: Securely retrieve passwords from KeePass databases
- **Automatic Encryption Detection**: Detect gocryptfs or cryfs automatically
- **CLI Interface**: Simple, intuitive command-line interface with **Typer**
- **Type Safety**: Full type annotations for IDE support and mypy compatibility
- **Password Prompting**: Securely prompt for passwords if not provided
- **Flexible Matching**: Match KeePass entries by title or encryption type

## Dependencies

- **typer** — CLI framework
- **pydantic** — Data validation
- **keepass-wrapper** — KeePass database interaction
- **mypy** — Static type checking
- **ruff** — Code linting

## Python Best Practices Used

- ✅ **Type hints**: Full type annotations throughout
- ✅ **Docstrings**: Clear module and function documentation
- ✅ **CLI design**: User-friendly argument parsing with Typer
- ✅ **Security**: Secure password handling with `getpass`
- ✅ **Code quality**: Automated linting with ruff
- ✅ **Type checking**: mypy validation
- ✅ **Project structure**: Clean package layout
- ✅ **Python versions**: Supports Python 3.10+

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## Author

AlexAndrewsAI <alex.andrews.ai@protonmail.com>
