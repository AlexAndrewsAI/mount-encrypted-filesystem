from pathlib import Path
from typing import List

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

    @field_validator("enctype")
    @classmethod
    def validate_enctype(cls, v: str | None) -> str | None:
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
    vaults: List[Config] = Field(description="List of vault configurations")

    model_config = {"title": "Batch Mount Configuration"}
