from pathlib import Path
from typing import Optional

import typer
from keepass_wrapper.keepass import KeePass  # type: ignore[import-untyped]

from mount_encrypted_filesystem.mount import mount_encrypted_fs

app = typer.Typer(help="Mount encrypted filesystems using passwords from KeePass")


@app.command()
def mount(
    vault_enc: str = typer.Argument(..., help="Path to encrypted vault"),
    vault_dec: str = typer.Argument(..., help="Path to mount decrypted vault"),
    database_path: Path = typer.Option(
        ..., "--database", "-d", help="Path to KeePass database file"
    ),
    enctype: Optional[str] = typer.Option(
        None,
        "--enctype",
        "-e",
        help="Encryption type (gocryptfs or cryfs). Auto-detected if not specified.",
    ),
    title: Optional[str] = typer.Option(
        None,
        "--title",
        "-t",
        help="Title to match in KeePass entries (defaults to enctype)",
    ),
) -> None:
    """Mount an encrypted filesystem using a password from KeePass."""
    # Initialize KeePass with database path
    kp = KeePass(database_path=str(database_path))

    # Mount the encrypted filesystem
    mount_encrypted_fs(
        vault_enc=vault_enc,
        vault_dec=vault_dec,
        kp=kp,
        enctype=enctype,
        title=title,
    )

    typer.echo("Mount operation completed.")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
