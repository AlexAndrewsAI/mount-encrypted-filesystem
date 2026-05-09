"""Command-line interface for mounting encrypted filesystems.

Provides typer-based CLI commands for mounting individual vaults and
batch processing multiple vaults from YAML configuration.
"""

import logging
from pathlib import Path

import typer
from keepass_wrapper.keepass import KeePass  # type: ignore[import-untyped]

from mount_encrypted_filesystem.batch import BatchMountError, batch_mount
from mount_encrypted_filesystem.mount import AlreadyMountedError, mount_encrypted_fs

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)

app = typer.Typer(help="Mount encrypted filesystems using passwords from KeePass")


@app.command()
def mount(
    vault_enc: Path = typer.Argument(..., help="Path to encrypted vault"),
    vault_dec: Path = typer.Argument(..., help="Path to mount decrypted vault"),
    database_path: Path = typer.Option(
        ..., "--database", "-d", help="Path to KeePass database file"
    ),
    enctype: str | None = typer.Option(
        None,
        "--enctype",
        "-e",
        help="Encryption type (gocryptfs or cryfs). Auto-detected if not specified.",
    ),
    title: str | None = typer.Option(
        None,
        "--title",
        "-t",
        help="Title to match in KeePass entries (defaults to enctype)",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        help="Timeout in seconds for mount command",
    ),
) -> None:
    """Mount an encrypted filesystem using a password from KeePass."""
    # Initialize KeePass with database path
    kp = KeePass(database_path=str(database_path))

    # Mount the encrypted filesystem
    try:
        mount_encrypted_fs(
            vault_enc=str(vault_enc),
            vault_dec=str(vault_dec),
            kp=kp,
            enctype=enctype,
            title=title,
            timeout=timeout,
        )
    except AlreadyMountedError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)

    typer.echo("Mount operation completed.")


@app.command()
def batch(
    batch_file: Path = typer.Argument(..., help="Path to batch YAML file"),
) -> None:
    """Mount multiple encrypted filesystems from a batch configuration file."""
    try:
        batch_mount(str(batch_file))
    except BatchMountError as e:
        typer.echo(f"Error: {e}")
        raise typer.Exit(1)

    typer.echo("Batch mount completed.")


def main() -> None:
    """Entry point for the CLI application."""
    app()


if __name__ == "__main__":
    main()
