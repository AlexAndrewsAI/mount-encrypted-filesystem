"""Core functionality for mounting encrypted filesystems.

Provides the main mount_encrypted_fs function that handles mounting
encrypted vaults using passwords from KeePass, with support for
gocryptfs and cryfs encryption types.
"""

import logging
import shlex
import shutil
import subprocess
from pathlib import Path

from keepass_wrapper.keepass import KeePass  # type: ignore[import-untyped]

from mount_encrypted_filesystem.config import (
    ENCTYPE_PATTERNS,
    SUPPORTED_ENCTYPES,
    Config,
    detect_enctype,
)

logger = logging.getLogger(__name__)


class AlreadyMountedError(RuntimeError):
    """Raised when attempting to mount a vault that is already mounted."""


def mount_encrypted_fs(
    kp: KeePass,
    vault_enc: str | None = None,
    vault_dec: str | None = None,
    enctype: str | None = None,
    title: str | None = None,
    return_kp: bool = False,
    timeout: int = 30,
    config: Config | None = None,
) -> KeePass | None:
    """Mount an encrypted filesystem using a password from KeePass.

    Args:
        kp: KeePass instance for password retrieval (required)
        vault_enc: Path to encrypted vault directory
        vault_dec: Path to mount decrypted vault
        enctype: Encryption type (gocryptfs or cryfs). Auto-detected if not specified.
        title: Title to match in KeePass entries (defaults to enctype)
        return_kp: Whether to return the KeePass object
        timeout: Timeout in seconds for mount command
        config: Config object (alternative to individual parameters)

    Returns:
        KeePass instance if return_kp=True, otherwise None

    Raises:
        ValueError: If required parameters are missing or validation fails
        RuntimeError: If encryption type is not installed or auto-detection fails
        AlreadyMountedError: If vault_dec is already a mount point

    """
    if config is not None:
        vault_enc = config.vault_enc
        vault_dec = config.vault_dec
        enctype = config.enctype
        title = config.title
        return_kp = config.return_kp
        timeout = config.timeout

    if vault_enc is None or vault_dec is None:
        raise ValueError("vault_enc and vault_dec are required")

    # Auto-detect enctype if not specified
    if enctype is None:
        detected = detect_enctype(vault_enc)
        if detected is None:
            raise RuntimeError(
                f"Could not auto-detect encryption type for '{vault_enc}'. "
                f"Expected one of: {', '.join(ENCTYPE_PATTERNS.values())}"
            )
        enctype = detected
        logger.info(f"Auto-detected encryption type: {enctype}")

    if title is None:
        title = enctype

    # Validate that enctype is supported
    if enctype not in SUPPORTED_ENCTYPES:
        raise ValueError(
            f"Unsupported enctype '{enctype}'. Must be in: "
            f"{', '.join(SUPPORTED_ENCTYPES)}"
        )

    # Validate that enctype is a valid system command
    if shutil.which(enctype) is None:
        raise RuntimeError(f"Encryption type '{enctype}' is not installed")

    # check if vault is already mounted
    if not Path(vault_dec).is_mount():
        logger.info(f"Need to mount {vault_dec} drive")

        for e in kp.entries:
            if title != e.title:
                continue

            # Run mount command with password passed securely via stdin
            cmd = [
                enctype,
                vault_enc,
                vault_dec,
            ]
            logger.debug(" ".join(shlex.quote(c) for c in cmd))
            p = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Pass password directly via stdin and capture output
            # NOTE: The KeePass library returns the password as a str, which in
            # CPython is immutable and may be interned. True secure memory wiping
            # is not possible here; this limitation is inherited from the wrapper.
            try:
                _, stderr = p.communicate(
                    input=e.get_password().encode(), timeout=timeout
                )

                if p.returncode != 0:
                    stderr_msg = stderr.decode(errors="replace").strip()
                    raise RuntimeError(
                        f"Mount failed with exit code {p.returncode}: {stderr_msg}"
                    )
                logger.info("Done.")
            except subprocess.TimeoutExpired:
                p.kill()
                raise RuntimeError(
                    f"Mount command timed out after {timeout} seconds. "
                    "Check your password and encryption settings."
                )
            break
        else:
            raise ValueError(f"No entry found with title '{title}'")
    else:
        raise AlreadyMountedError(f"{vault_dec} is already mounted")

    if return_kp:
        return kp

    return None
