from pathlib import Path

from pydantic import BaseModel, Field, field_validator

SUPPORTED_ENCTYPES = ["gocryptfs", "cryfs"]

# Detection patterns for each encryption type
ENCTYPE_PATTERNS = {
    "gocryptfs": "gocryptfs.conf",
    "cryfs": "cryfs.config",
}


def detect_enctype(vault_enc: str) -> str | None:
    """Detect encryption type based on files present in the encrypted vault."""
    vault_path = Path(vault_enc)
    if not vault_path.exists():
        return None

    for enctype, pattern in ENCTYPE_PATTERNS.items():
        if (vault_path / pattern).exists():
            return enctype
    return None


class Config(BaseModel):
    """Configuration for mounting a single encrypted vault.

    Attributes:
        vault_enc: Path to encrypted vault directory.
        vault_dec: Path to mount decrypted vault.
        enctype: Encryption type (gocryptfs or cryfs). Auto-detected if not specified.
        title: Title to match in KeePass entries (defaults to enctype).
        return_kp: Whether to return the KeePass object.
        timeout: Timeout in seconds for mount command.

    """

    vault_enc: str = Field(description="Path to encrypted vault")
    vault_dec: str = Field(description="Path to mount decrypted vault")
    enctype: str | None = Field(
        default=None,
        description=(
            f"Encryption type {SUPPORTED_ENCTYPES}. Auto-detected if not specified."
        ),
    )
    title: str | None = Field(
        default=None,
        description="Title to match in KeePass entries (defaults to enctype)",
    )
    return_kp: bool = Field(
        default=False, description="Whether to return the KeePass object"
    )
    timeout: int = Field(
        default=30, description="Timeout in seconds for mount command"
    )

    @field_validator("vault_dec")
    @classmethod
    def validate_vault_dec(cls, v: str) -> str:
        """Validate that vault_dec directory is empty or a mount point.

        Args:
            v: Path to the decrypted vault mount directory.

        Returns:
            The validated path string.

        Raises:
            ValueError: If the directory exists, is not empty, and is not a mount point.

        """
        vault_path = Path(v)
        if (
            vault_path.exists()
            and any(vault_path.iterdir())
            and not vault_path.is_mount()
        ):
            raise ValueError(f"vault_dec directory '{v}' must be empty")
        return v

    @field_validator("enctype")
    @classmethod
    def validate_enctype(cls, v: str | None) -> str | None:
        """Validate that enctype is a supported encryption type.

        Args:
            v: Encryption type string or None.

        Returns:
            The validated encryption type string or None.

        Raises:
            ValueError: If enctype is not in SUPPORTED_ENCTYPES.

        """
        if v is None:
            return None
        if v not in SUPPORTED_ENCTYPES:
            raise ValueError(
                f"Unsupported enctype '{v}'. Must be in: "
                f"{', '.join(SUPPORTED_ENCTYPES)}"
            )
        return v

    model_config = {"title": "Mount Encrypted Filesystem Config"}


class BatchConfig(BaseModel):
    """Configuration for batch mounting multiple vaults."""

    database_path: str = Field(description="Path to KeePass database file")
    vaults: list[Config] = Field(description="List of vault configurations")

    model_config = {"title": "Batch Mount Configuration"}
