import subprocess
from pathlib import Path

# Import keypass related stuff
from keepass_wrapper.keepass import KeePass  # type: ignore[import-untyped]

from mount_encrypted_filesystem.config import (
    ENCTYPE_PATTERNS,
    SUPPORTED_ENCTYPES,
    Config,
    detect_enctype,
)


def mount_encrypted_fs(
    vault_enc: str | None = None,
    vault_dec: str | None = None,
    kp: KeePass | None = None,
    enctype: str | None = None,
    title: str | None = None,
    return_kp: bool = False,
    config: Config | None = None,
) -> KeePass | None:
    if config is not None:
        vault_enc = config.vault_enc
        vault_dec = config.vault_dec
        enctype = config.enctype
        title = config.title
        return_kp = config.return_kp

    # Auto-detect enctype if not specified
    if enctype is None:
        if vault_enc is None:
            raise ValueError("Cannot auto-detect enctype: vault_enc is not specified")
        detected = detect_enctype(vault_enc)
        if detected is None:
            raise RuntimeError(
                f"Could not auto-detect encryption type for '{vault_enc}'. "
                f"Expected one of: {', '.join(ENCTYPE_PATTERNS.values())}"
            )
        enctype = detected
        print(f"Auto-detected encryption type: {enctype}")

    if title is None:
        title = enctype

    # Validate that enctype is supported
    if enctype not in SUPPORTED_ENCTYPES:
        raise ValueError(
            f"Unsupported enctype '{enctype}'. Must be in: "
            f"{', '.join(SUPPORTED_ENCTYPES)}"
        )

    # Validate that enctype is a valid system command
    result = subprocess.run(["which", enctype], capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"Encryption type '{enctype}' is not installed or not found in PATH"
        )

    # check if gocrypt drive decrypted
    if not Path(f"{vault_dec}/README.md").exists():
        print(f"Need to mount {vault_dec} drive")

        if kp is None:
            raise ValueError("kp (KeePass instance) is required but was not provided")

        for e in kp.entries:
            if title != e.title:
                continue
            print(vars(e))
            password = e.get_password()
            # Run mount command with password passed securely via stdin
            cmd = [
                enctype,
                f"{vault_enc}",
                f"{vault_dec}",
            ]
            print(" ".join(cmd))
            p = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
            )

            # Pass password directly
            p.communicate(input=password.encode())
            print("Done.")
            break
        else:
            raise ValueError(f"No entry found with title '{title}'")
    else:
        print(f"{vault_dec} already Mounted")

    if return_kp:
        if kp is None:
            raise ValueError("return_kp is True but kp is None")
        return kp

    return None
