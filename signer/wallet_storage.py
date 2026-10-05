import json
import os
import uuid
from datetime import datetime, timezone

from signer.luks_manager import get_storage_root


WALLETS_DIRECTORY = "wallets"
ACTIVE_DIRECTORY = "active"
ARCHIVE_DIRECTORY = "archive"

METADATA_FILENAME = "wallet.json"
SECRET_FILENAME = "secret.json"


def get_wallets_root():
    """Return the root directory containing all wallets."""

    storage_root = get_storage_root()

    return os.path.join(
        storage_root,
        WALLETS_DIRECTORY,
    )


def get_active_directory():
    """Return the directory containing the active wallet."""

    return os.path.join(
        get_wallets_root(),
        ACTIVE_DIRECTORY,
    )


def get_archive_directory():
    """Return the directory containing archived wallets."""

    return os.path.join(
        get_wallets_root(),
        ARCHIVE_DIRECTORY,
    )


def get_active_metadata_path():
    """Return the path to the active wallet metadata."""

    return os.path.join(
        get_active_directory(),
        METADATA_FILENAME,
    )


def get_active_secret_path():
    """Return the path to the active wallet secret."""

    return os.path.join(
        get_active_directory(),
        SECRET_FILENAME,
    )


def ensure_wallet_storage():
    """Create the wallet storage directory structure."""

    wallets_root = get_wallets_root()

    os.makedirs(
        wallets_root,
        mode=0o700,
        exist_ok=True,
    )

    os.makedirs(
        get_active_directory(),
        mode=0o700,
        exist_ok=True,
    )

    os.makedirs(
        get_archive_directory(),
        mode=0o700,
        exist_ok=True,
    )

    return wallets_root


def create_wallet_metadata(name):
    """Create metadata for a new wallet."""

    name = name.strip()

    if not name:
        raise ValueError("Wallet name cannot be empty.")

    wallet_id = str(uuid.uuid4())

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    return {
        "format_version": 1,
        "wallet_id": wallet_id,
        "wallet_name": name,
        "created_at": created_at,
        "archived_at": None,
        "wallet_type": "bip39",
    }


def save_metadata(metadata):
    """Save active wallet metadata."""

    ensure_wallet_storage()

    wallet_path = get_active_metadata_path()

    with open(
        wallet_path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metadata,
            file,
            indent=4,
        )

    os.chmod(
        wallet_path,
        0o600,
    )

    return wallet_path


def load_active_metadata():
    """Load metadata for the active wallet."""

    wallet_path = get_active_metadata_path()

    if not os.path.isfile(wallet_path):
        return None

    with open(
        wallet_path,
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)



def wallet_name_exists(name):
    """Return True if a wallet with this name already exists."""

    name = name.strip().casefold()

    if not name:
        return False

    active_metadata = load_active_metadata()

    if active_metadata is not None:
        active_name = active_metadata.get(
            "wallet_name",
            "",
        ).strip().casefold()

        if active_name == name:
            return True

    archive_directory = get_archive_directory()

    if not os.path.isdir(archive_directory):
        return False

    for wallet_id in os.listdir(archive_directory):
        wallet_directory = os.path.join(
            archive_directory,
            wallet_id,
        )

        if not os.path.isdir(wallet_directory):
            continue

        metadata_path = os.path.join(
            wallet_directory,
            METADATA_FILENAME,
        )

        if not os.path.isfile(metadata_path):
            continue

        with open(
            metadata_path,
            "r",
            encoding="utf-8",
        ) as file:
            metadata = json.load(file)

        archived_name = metadata.get(
            "wallet_name",
            "",
        ).strip().casefold()

        if archived_name == name:
            return True

    return False



def save_active_secret(mnemonic):
    """Save the active wallet mnemonic."""

    if not mnemonic:
        raise ValueError("Mnemonic cannot be empty.")

    ensure_wallet_storage()

    secret_path = get_active_secret_path()

    secret = {
        "mnemonic": mnemonic,
    }

    with open(
        secret_path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            secret,
            file,
            indent=4,
        )

    os.chmod(
        secret_path,
        0o600,
    )

    return secret_path


def load_active_secret():
    """Load the active wallet mnemonic."""

    secret_path = get_active_secret_path()

    if not os.path.isfile(secret_path):
        return None

    with open(
        secret_path,
        "r",
        encoding="utf-8",
    ) as file:
        secret = json.load(file)

    return secret["mnemonic"]



def delete_active_wallet():
    """Delete the active wallet from encrypted storage."""

    metadata = load_active_metadata()

    if metadata is None:
        return False

    secret_path = get_active_secret_path()
    metadata_path = get_active_metadata_path()

    if not os.path.isfile(secret_path):
        raise RuntimeError(
            "Active wallet secret is missing."
        )

    os.remove(secret_path)
    os.remove(metadata_path)

    return True


def delete_archived_wallet(wallet_id):
    """Delete an archived wallet from encrypted storage."""

    if not wallet_id:
        raise ValueError(
            "No wallet ID was provided."
        )

    archive_directory = os.path.join(
        get_archive_directory(),
        wallet_id,
    )

    if not os.path.isdir(archive_directory):
        raise RuntimeError(
            "The selected archived wallet does not exist."
        )

    metadata_path = os.path.join(
        archive_directory,
        METADATA_FILENAME,
    )

    secret_path = os.path.join(
        archive_directory,
        SECRET_FILENAME,
    )

    if not os.path.isfile(metadata_path):
        raise RuntimeError(
            "The archived wallet metadata is missing."
        )

    if not os.path.isfile(secret_path):
        raise RuntimeError(
            "The archived wallet secret is missing."
        )

    with open(
        metadata_path,
        "r",
        encoding="utf-8",
    ) as file:
        metadata = json.load(file)

    if metadata.get("wallet_id") != wallet_id:
        raise RuntimeError(
            "The archived wallet ID does not match its directory."
        )

    os.remove(secret_path)
    os.remove(metadata_path)
    os.rmdir(archive_directory)

    return True




def archive_active_wallet():
    """Move the active wallet into the archive."""

    metadata = load_active_metadata()

    if metadata is None:
        return False

    wallet_id = metadata.get("wallet_id")

    if not wallet_id:
        raise RuntimeError(
            "Active wallet metadata has no wallet ID."
        )

    active_directory = get_active_directory()
    archive_directory = os.path.join(
        get_archive_directory(),
        wallet_id,
    )

    if os.path.exists(archive_directory):
        raise RuntimeError(
            f"Archived wallet already exists: {wallet_id}"
        )

    secret_path = get_active_secret_path()

    if not os.path.isfile(secret_path):
        raise RuntimeError(
            "Active wallet secret is missing."
        )

    metadata["archived_at"] = datetime.now(
        timezone.utc
    ).isoformat()

    os.makedirs(
        archive_directory,
        mode=0o700,
        exist_ok=False,
    )

    try:
        metadata_path = os.path.join(
            archive_directory,
            METADATA_FILENAME,
        )

        archive_secret_path = os.path.join(
            archive_directory,
            SECRET_FILENAME,
        )

        with open(
            metadata_path,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                metadata,
                file,
                indent=4,
            )

        os.chmod(
            metadata_path,
            0o600,
        )

        os.replace(
            secret_path,
            archive_secret_path,
        )

        os.chmod(
            archive_secret_path,
            0o600,
        )

        os.remove(
            get_active_metadata_path()
        )

    except Exception:
        if os.path.isdir(archive_directory):
            import shutil

            shutil.rmtree(
                archive_directory
            )

        raise

    return True


def load_archived_wallet(wallet_id):
    """Make an archived wallet the active wallet."""

    if not wallet_id:
        raise ValueError(
            "No wallet ID was provided."
        )

    archive_directory = os.path.join(
        get_archive_directory(),
        wallet_id,
    )

    archive_metadata_path = os.path.join(
        archive_directory,
        METADATA_FILENAME,
    )

    archive_secret_path = os.path.join(
        archive_directory,
        SECRET_FILENAME,
    )

    if not os.path.isdir(archive_directory):
        raise RuntimeError(
            "The selected archived wallet does not exist."
        )

    if not os.path.isfile(archive_metadata_path):
        raise RuntimeError(
            "The selected wallet metadata is missing."
        )

    if not os.path.isfile(archive_secret_path):
        raise RuntimeError(
            "The selected wallet secret is missing."
        )

    active_directory = get_active_directory()

    active_metadata_path = get_active_metadata_path()
    active_secret_path = get_active_secret_path()

    os.makedirs(
        active_directory,
        mode=0o700,
        exist_ok=True,
    )

    with open(
        archive_metadata_path,
        "r",
        encoding="utf-8",
    ) as file:
        metadata = json.load(file)

    if metadata.get("wallet_id") != wallet_id:
        raise RuntimeError(
            "The archived wallet ID does not match its directory."
        )

    with open(
        archive_secret_path,
        "r",
        encoding="utf-8",
    ) as file:
        secret = json.load(file)

    if not secret.get("mnemonic"):
        raise RuntimeError(
            "The archived wallet secret is invalid."
        )

    # First archive the currently active wallet.
    archive_active_wallet()

    try:
        metadata["archived_at"] = None

        with open(
            active_metadata_path,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                metadata,
                file,
                indent=4,
            )

        os.chmod(
            active_metadata_path,
            0o600,
        )

        os.replace(
            archive_secret_path,
            active_secret_path,
        )

        os.remove(
            archive_metadata_path
        )

        os.rmdir(
            archive_directory
        )

    except Exception:
        raise

    return metadata, secret["mnemonic"]
