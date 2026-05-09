"""Mount encrypted filesystems using passwords from KeePass.

This package provides utilities for mounting encrypted filesystems (gocryptfs, cryfs)
using passwords retrieved from a KeePass database.
"""

from mount_encrypted_filesystem.batch import BatchMountError, batch_mount
from mount_encrypted_filesystem.config import (
    ENCTYPE_PATTERNS,
    SUPPORTED_ENCTYPES,
    BatchConfig,
    Config,
    detect_enctype,
)
from mount_encrypted_filesystem.mount import mount_encrypted_fs

__version__ = "0.2.1"
__all__ = [
    "ENCTYPE_PATTERNS",
    "SUPPORTED_ENCTYPES",
    "BatchConfig",
    "BatchMountError",
    "Config",
    "batch_mount",
    "detect_enctype",
    "mount_encrypted_fs",
]
