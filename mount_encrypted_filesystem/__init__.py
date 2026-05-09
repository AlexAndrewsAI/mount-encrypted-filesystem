"""Mount encrypted filesystems using passwords stored in KeePass.

This package provides a command-line tool (via Typer) for mounting encrypted
filesystems like gocryptfs or cryfs using credentials stored in KeePass.

Main components:
    - mount: Core mounting functionality
    - config: Configuration and encryption type detection

Example:
    >>> from mount_encrypted_filesystem.mount import mount_encrypted_fs
    >>> from keepass_wrapper.keepass import KeePass
    >>> kp = KeePass("database.kdbx", "password")
    >>> mount_encrypted_fs(
    ...     vault_enc="/path/to/encrypted",
    ...     vault_dec="/path/to/mount",
    ...     kp=kp,
    ...     enctype="gocryptfs"
    ... )
"""

__version__ = "0.1.0"
__author__ = "AlexAndrewsAI"

from mount_encrypted_filesystem.mount import mount_encrypted_fs

__all__ = ["mount_encrypted_fs"]
