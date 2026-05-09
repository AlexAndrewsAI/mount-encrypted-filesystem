from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mount_encrypted_filesystem import Config, mount_encrypted_fs
from mount_encrypted_filesystem.config import BatchConfig

# Test filesystem paths
TEST_DIR = Path(__file__).parent
CRYFS_ENC = TEST_DIR / "filesystems" / "cryfs"
GOCRYPTFS_ENC = TEST_DIR / "filesystems" / "gocryptfs"
MNT_BASE = TEST_DIR / "filesystems" / "mnt"


class MockKeePassEntry:
    """Mock KeePass entry with title and password."""

    def __init__(self, title: str, password: str) -> None:
        self.title = title
        self._password = password

    def get_password(self) -> str:
        return self._password


class MockKeePass:
    """Mock KeePass database with entries."""

    def __init__(self, entries: list[MockKeePassEntry]) -> None:
        self.entries = entries


def test_mount_encrypted_fs_import() -> None:
    """Test that mount_encrypted_fs can be imported."""
    assert callable(mount_encrypted_fs)


@pytest.fixture
def mock_cryfs_kp() -> MockKeePass:
    """Mock KeePass with cryfs entry (password: c1)."""
    entry = MockKeePassEntry(title="cryfs", password="c1")
    return MockKeePass(entries=[entry])


@pytest.fixture
def mock_gocryptfs_kp() -> MockKeePass:
    """Mock KeePass with gocryptfs entry (password: g1)."""
    entry = MockKeePassEntry(title="gocryptfs", password="g1")
    return MockKeePass(entries=[entry])


def test_mount_cryfs(mock_cryfs_kp: MockKeePass, tmp_path: Path) -> None:
    """Test mounting cryfs filesystem with password 'c1'."""
    mnt_dir = tmp_path / "cryfs_mnt"
    mnt_dir.mkdir()

    # Mock the which command and subprocess calls
    with patch("subprocess.run") as mock_run, \
         patch("subprocess.Popen") as mock_popen, \
         patch("time.sleep"):

        mock_run.return_value = MagicMock(returncode=0)
        mock_proc = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        mount_encrypted_fs(
            vault_enc=str(CRYFS_ENC),
            vault_dec=str(mnt_dir),
            kp=mock_cryfs_kp,
            enctype="cryfs",
            title="cryfs",
        )

        # Verify cryfs command was found
        mock_run.assert_called_once_with(
            ["which", "cryfs"], capture_output=True, check=False
        )

        # Verify cryfs was called
        assert mock_popen.call_count == 1


def test_mount_gocryptfs(mock_gocryptfs_kp: MockKeePass, tmp_path: Path) -> None:
    """Test mounting gocryptfs filesystem with password 'g1'."""
    mnt_dir = tmp_path / "gocryptfs_mnt"
    mnt_dir.mkdir()

    # Mock the which command and subprocess calls
    with patch("subprocess.run") as mock_run, \
         patch("subprocess.Popen") as mock_popen:

        mock_run.return_value = MagicMock(returncode=0)
        mock_proc = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        mount_encrypted_fs(
            vault_enc=str(GOCRYPTFS_ENC),
            vault_dec=str(mnt_dir),
            kp=mock_gocryptfs_kp,
            enctype="gocryptfs",
            title="gocryptfs",
        )

        # Verify gocryptfs command was found
        mock_run.assert_called_once_with(
            ["which", "gocryptfs"], capture_output=True, check=False
        )

        # Verify gocryptfs was called
        assert mock_popen.call_count == 1


def test_already_mounted_skips_mount(
    mock_cryfs_kp: MockKeePass, tmp_path: Path
) -> None:
    """Test that mounting is skipped if already mounted (README.md exists)."""
    mnt_dir = tmp_path / "already_mnt"
    mnt_dir.mkdir()
    # Create README.md to simulate already mounted
    (mnt_dir / "README.md").write_text("cryfs")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)

        mount_encrypted_fs(
            vault_enc=str(CRYFS_ENC),
            vault_dec=str(mnt_dir),
            kp=mock_cryfs_kp,
            enctype="cryfs",
            title="cryfs",
        )

        # Only "which" should be called, not the mount commands
        assert mock_run.call_count == 1


def test_missing_enctype_raises_error() -> None:
    with patch("mount_encrypted_filesystem.mount.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)

        with pytest.raises(
            RuntimeError, match="Encryption type 'gocryptfs' is not installed"
        ):
            mount_encrypted_fs(
                vault_enc="/fake/enc",
                vault_dec="/fake/dec",
                enctype="gocryptfs",
            )


def test_mount_with_config(mock_gocryptfs_kp: MockKeePass, tmp_path: Path) -> None:
    """Test mounting using Config object."""
    mnt_dir = tmp_path / "config_mnt"
    mnt_dir.mkdir()

    config = Config(
        vault_enc=str(GOCRYPTFS_ENC),
        vault_dec=str(mnt_dir),
        enctype="gocryptfs",
        title="gocryptfs",
    )

    with patch("subprocess.run") as mock_run, \
         patch("subprocess.Popen") as mock_popen:

        mock_run.return_value = MagicMock(returncode=0)
        mock_proc = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        mount_encrypted_fs(kp=mock_gocryptfs_kp, config=config)

        # Verify gocryptfs command was found
        mock_run.assert_called_once_with(
            ["which", "gocryptfs"], capture_output=True, check=False
        )


def test_default_title_from_enctype(mock_cryfs_kp: MockKeePass, tmp_path: Path) -> None:
    """Test that title defaults to enctype when not provided."""
    mnt_dir = tmp_path / "default_title_mnt"
    mnt_dir.mkdir()

    with patch("subprocess.run") as mock_run, \
         patch("subprocess.Popen") as mock_popen:

        mock_run.return_value = MagicMock(returncode=0)
        mock_proc = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        # No title provided, should default to "cryfs"
        mount_encrypted_fs(
            vault_enc=str(CRYFS_ENC),
            vault_dec=str(mnt_dir),
            kp=mock_cryfs_kp,
            enctype="cryfs",
        )

        # Should use "cryfs" as title and find the matching entry
        mock_run.assert_called_once_with(
            ["which", "cryfs"], capture_output=True, check=False
        )


def test_return_kp(mock_cryfs_kp: MockKeePass, tmp_path: Path) -> None:
    """Test that return_kp returns the KeePass object."""
    mnt_dir = tmp_path / "return_kp_mnt"
    mnt_dir.mkdir()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        # Already mounted to avoid subprocess.Popen
        (mnt_dir / "README.md").write_text("cryfs")

        result = mount_encrypted_fs(
            vault_enc=str(CRYFS_ENC),
            vault_dec=str(mnt_dir),
            kp=mock_cryfs_kp,
            enctype="cryfs",
            return_kp=True,
        )

        assert result is mock_cryfs_kp


@pytest.fixture
def mock_batch_kp() -> MockKeePass:
    """Mock KeePass with entries for batch processing (custom and cryfs)."""
    entries = [
        MockKeePassEntry(title="custom", password="g1"),
        MockKeePassEntry(title="cryfs", password="c1"),
    ]
    return MockKeePass(entries=entries)


def test_batch_processing(mock_batch_kp: MockKeePass, tmp_path: Path) -> None:
    """Test batch processing of multiple vaults using mock KeePass."""
    # Create mount directories
    gocrypt_mnt = tmp_path / "gocryptfs_dec"
    cryfs_mnt = tmp_path / "cryfs_dec"
    gocrypt_mnt.mkdir()
    cryfs_mnt.mkdir()

    # Create batch config similar to tests/batch.yml
    batch_config = BatchConfig(
        database_path="tests/enc.kdbx",
        vaults=[
            Config(
                vault_enc=str(GOCRYPTFS_ENC),
                vault_dec=str(gocrypt_mnt),
                title="custom",
            ),
            Config(
                vault_enc=str(CRYFS_ENC),
                vault_dec=str(cryfs_mnt),
            ),
        ],
    )

    with patch("subprocess.run") as mock_run, \
         patch("subprocess.Popen") as mock_popen:

        mock_run.return_value = MagicMock(returncode=0)
        mock_proc = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        # Process batch similar to CLI batch command
        for vault_config in batch_config.vaults:
            mount_encrypted_fs(
                vault_enc=vault_config.vault_enc,
                vault_dec=vault_config.vault_dec,
                kp=mock_batch_kp,
                enctype=vault_config.enctype,
                title=vault_config.title,
            )

        # Verify both vaults were mounted (2 Popen calls for 2 vaults)
        assert mock_popen.call_count == 2
