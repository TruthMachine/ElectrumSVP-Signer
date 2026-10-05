import asyncio
import os
import json
import subprocess
import sys


IS_LINUX = sys.platform.startswith("linux")


if IS_LINUX:
    from dbus_next import BusType
    from dbus_next.aio import MessageBus


STORAGE_DIRECTORY = "ElectrumSVP Signer"

UDISKS2_SERVICE = "org.freedesktop.UDisks2"
UDISKS2_ENCRYPTED_INTERFACE = "org.freedesktop.UDisks2.Encrypted"



def initialize_luks_device(
    device_path,
    storage_name,
    passphrase,
):
    """Initialize a removable USB device as LUKS2 + ext4 storage."""

    if not IS_LINUX:
        raise RuntimeError(
            "Encrypted USB wallet storage is currently "
            "supported on Linux only."
        )

    if not device_path:
        raise ValueError(
            "No device path was provided."
        )

    if not storage_name:
        raise ValueError(
            "A storage name is required."
        )

    if not passphrase:
        raise ValueError(
            "A passphrase is required."
        )

    storage_name = storage_name.strip()

    if not storage_name:
        raise ValueError(
            "A storage name is required."
        )

    devices = find_removable_storage_devices()

    selected_device = None

    for device in devices:
        if device["path"] == device_path:
            selected_device = device
            break

    if selected_device is None:
        raise ValueError(
            "The selected device is no longer available as a "
            "removable USB device."
        )

    if selected_device["mountpoint"]:
        raise ValueError(
            "The selected device is currently mounted."
        )

    import asyncio

    from dbus_next import BusType, Variant
    from dbus_next.aio import MessageBus

    async def format_device():
        bus = await MessageBus(
            bus_type=BusType.SYSTEM
        ).connect()

        try:
            device_name = device_path.split("/")[-1]

            object_path = (
                "/org/freedesktop/UDisks2/block_devices/"
                + device_name
            )

            introspection = await bus.introspect(
                "org.freedesktop.UDisks2",
                object_path,
                )

            proxy = bus.get_proxy_object(
                "org.freedesktop.UDisks2",
                object_path,
                introspection,
            )

            block = proxy.get_interface(
                "org.freedesktop.UDisks2.Block"
            )

            options = {
                "encrypt.passphrase": Variant(
                    "s",
                    passphrase,
                ),
                "encrypt.type": Variant(
                    "s",
                    "luks2",
                ),
                "label": Variant(
                    "s",
                    storage_name,
                ),
                "take-ownership": Variant(
                    "b",
                    True,
                ),
            }

            await block.call_format(
                "ext4",
                options,
            )

        finally:
            bus.disconnect()

    asyncio.run(
        format_device()
    )



def find_luks_device():
    """Find the removable USB device containing the LUKS container."""

    result = subprocess.run(
        [
            "lsblk",
            "-nrpo",
            "NAME,TYPE,FSTYPE,RM,TRAN",
        ],
        text=True,
        capture_output=True,
        check=True,
    )

    for line in result.stdout.splitlines():
        fields = line.split()

        if len(fields) != 5:
            continue

        device, device_type, filesystem, removable, transport = fields

        if device_type != "disk":
            continue

        if filesystem != "crypto_LUKS":
            continue

        if removable != "1":
            continue

        if transport != "usb":
            continue

        return device

    return None



def find_removable_storage_devices():
    """Return removable block devices suitable for storage initialization."""

    try:
        result = subprocess.run(
            [
                "lsblk",
                "-J",
                "-o",
                "NAME,PATH,SIZE,TYPE,RM,TRAN,MOUNTPOINT",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        data = json.loads(result.stdout)

    except Exception:
        return []

    devices = []

    for device in data.get("blockdevices", []):
        if device.get("type") != "disk":
            continue

        if not device.get("rm"):
            continue

        if device.get("tran") != "usb":
            continue

        devices.append(
            {
                "name": device.get("name"),
                "path": device.get("path"),
                "size": device.get("size"),
                "mountpoint": device.get("mountpoint"),
            }
        )

    return devices



def find_filesystem_device():
    """Find the filesystem device inside the unlocked LUKS container."""

    luks_device = find_luks_device()

    if luks_device is None:
        return None

    result = subprocess.run(
        [
            "lsblk",
            "-nrpo",
            "NAME,TYPE,FSTYPE,PKNAME",
        ],
        text=True,
        capture_output=True,
        check=True,
    )

    for line in result.stdout.splitlines():
        fields = line.split()

        if len(fields) != 4:
            continue

        device, device_type, filesystem, parent_name = fields

        if device_type != "crypt":
            continue

        if filesystem != "ext4":
            continue

        if parent_name == luks_device:
            return device

    return None


def find_mount_path(device):
    result = subprocess.run(
        ["findmnt", "-n", "-o", "TARGET", device],
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        return None

    mount_paths = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    if not mount_paths:
        return None

    for mount_path in mount_paths:
        if mount_path.startswith("/media/"):
            return mount_path

    return mount_paths[0]


def get_storage_root():
    """Return the root directory of the encrypted signer storage."""

    device = find_filesystem_device()

    if device is None:
        raise RuntimeError("Encrypted storage is not unlocked.")

    mount_path = find_mount_path(device)

    if mount_path is None:
        raise RuntimeError("Encrypted storage is not mounted.")

    return os.path.join(mount_path, STORAGE_DIRECTORY)


def ensure_storage_layout():
    """Create the signer storage directory if it does not exist."""

    storage_root = get_storage_root()

    os.makedirs(storage_root, mode=0o700, exist_ok=True)

    return storage_root


def device_to_udisks_object(device):
    if not device.startswith("/dev/"):
        raise ValueError(f"Invalid device path: {device}")

    device_name = device[5:]
    object_name = device_name.replace("-", "_2d")

    return (
        "/org/freedesktop/UDisks2/block_devices/"
        + object_name
    )



def get_storage_label():
    """Return the filesystem label of the mounted wallet storage."""

    device = find_filesystem_device()

    if device is None:
        return None

    mount_path = find_mount_path(device)

    if mount_path is None:
        return None

    try:
        result = subprocess.run(
            [
                "lsblk",
                "-no",
                "LABEL",
                device,
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        label = result.stdout.strip()

        if label:
            return label

    except Exception:
        pass

    return None



def unlock(passphrase):
    """Unlock the discovered LUKS device through UDisks2 D-Bus."""

    device = find_luks_device()

    if device is None:
        raise RuntimeError("LUKS device not found.")

    object_path = device_to_udisks_object(device)

    async def _unlock():
        bus = await MessageBus(
            bus_type=BusType.SYSTEM
        ).connect()

        try:
            introspection = await bus.introspect(
                UDISKS2_SERVICE,
                object_path,
            )

            proxy_object = bus.get_proxy_object(
                UDISKS2_SERVICE,
                object_path,
                introspection,
            )

            encrypted = proxy_object.get_interface(
                UDISKS2_ENCRYPTED_INTERFACE
            )

            return await encrypted.call_unlock(
                passphrase,
                {},
            )

        finally:
            bus.disconnect()

    try:
        return asyncio.run(_unlock())

    except Exception as e:
        error = str(e)

        if "No key available to unlock device" in error:
            raise RuntimeError(
                "Incorrect LUKS passphrase."
            ) from e

        raise RuntimeError(
            f"Could not unlock LUKS device: {error}"
        ) from e


def mount():
    device = find_filesystem_device()

    if device is None:
        raise RuntimeError("Unlocked filesystem not found.")

    existing_mount = find_mount_path(device)

    if existing_mount is not None:
        return existing_mount

    result = subprocess.run(
        ["udisksctl", "mount", "-b", device],
        check=True,
        text=True,
        capture_output=True,
    )

    output = result.stdout.strip()
    marker = " at "

    if marker not in output:
        raise RuntimeError(f"Could not determine mount path: {output}")

    return output.split(marker, 1)[1].strip()


def unmount():
    device = find_filesystem_device()

    if device is None:
        return False

    existing_mount = find_mount_path(device)

    if existing_mount is None:
        return False

    subprocess.run(
        ["udisksctl", "unmount", "-b", device],
        check=True,
        text=True,
    )

    return True


def lock():
    luks_device = find_luks_device()

    if luks_device is None:
        return False

    filesystem_device = find_filesystem_device()

    if filesystem_device is None:
        return False

    existing_mount = find_mount_path(filesystem_device)

    if existing_mount is not None:
        raise RuntimeError(
            f"Cannot lock LUKS device while filesystem is mounted at "
            f"{existing_mount}."
        )

    subprocess.run(
        ["udisksctl", "lock", "-b", luks_device],
        check=True,
        text=True,
    )

    return True


def open_storage(passphrase):
    filesystem_device = find_filesystem_device()
    unlocked_here = False

    if filesystem_device is None:
        unlock(passphrase)
        unlocked_here = True

    try:
        return mount()
    except Exception:
        if unlocked_here:
            try:
                lock()
            except Exception:
                pass

        raise


def close_storage():
    unmount()
    return lock()

