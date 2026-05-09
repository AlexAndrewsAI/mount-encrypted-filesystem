import logging
from pathlib import Path
from typing import Optional

import yaml  # type: ignore[import-untyped]
from keepass_wrapper.keepass import KeePass  # type: ignore[import-untyped]
from pydantic import ValidationError  # type: ignore[import-untyped]

from mount_encrypted_filesystem.config import BatchConfig
from mount_encrypted_filesystem.mount import AlreadyMountedError, mount_encrypted_fs

logger = logging.getLogger(__name__)


class BatchMountError(Exception):
    """Raised when batch mount configuration or execution fails."""


def batch_mount(
    batch_file: str | Path,
    kp: Optional[KeePass] = None,
    return_kp: bool = False,
) -> KeePass | None:
    """Mount multiple encrypted filesystems from a batch configuration file.

    Args:
        batch_file: Path to the batch YAML configuration file.
        kp: Optional KeePass instance. If provided, overrides the database_path
            specified in the YAML file.
        return_kp: Whether to return the KeePass object.

    Returns:
        KeePass instance if return_kp=True, otherwise None.

    Raises:
        BatchMountError: If the configuration is invalid or no vaults are specified.
    """
    batch_path = Path(batch_file)
    with open(batch_path, encoding="utf-8") as f:
        raw_data = yaml.safe_load(f)

    try:
        batch_config = BatchConfig(**raw_data)
    except ValidationError as e:
        raise BatchMountError(f"Invalid batch configuration: {e}") from e

    if not batch_config.vaults:
        raise BatchMountError("No vaults specified in batch configuration")

    if kp is None:
        kp = KeePass(database_path=batch_config.database_path)

    mounted_count = 0
    for vault_config in batch_config.vaults:
        try:
            logger.info(
                f"Mounting {vault_config.vault_enc} -> {vault_config.vault_dec}..."
            )
            mount_encrypted_fs(
                vault_enc=vault_config.vault_enc,
                vault_dec=vault_config.vault_dec,
                kp=kp,
                enctype=vault_config.enctype,
                title=vault_config.title,
            )
            logger.info(f"Successfully mounted {vault_config.vault_enc}")
            mounted_count += 1
        except (ValueError, AlreadyMountedError) as e:
            logger.warning(
                f"Skipping {vault_config.vault_enc}: {e}"
            )

    logger.info(
        f"Batch mount completed. {mounted_count}/{len(batch_config.vaults)} "
        "vault(s) mounted."
    )

    if return_kp:
        return kp

    return None
