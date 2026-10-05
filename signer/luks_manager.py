import asyncio
import json
import os
import subprocess
import sys


IS_LINUX = sys.platform.startswith("linux")


if IS_LINUX:
    from dbus_next import BusType, Variant
    from dbus_next.aio import MessageBus


STORAGE_DIRECTORY = "ElectrumSVP Signer"

UDISKS2_SERVICE = "org.freedesktop.UDisks2"
UDISKS2_BLOCK_INTERFACE = "org.freedesktop.UDisks2.Block"
UDISKS2_ENCRYPTED_INTERFACE = "org.freedesktop.UDisks2.Encrypted"


def initialize_luks_device(
    device_path,
    storage_name,
    passphrase,
):
    """
    Initialize a removable USB device as LUKS2 + ext4 storage.

    WARNING:
        This permanently erases the selected device.
    """

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

    mounted_devices = []

    def collect_mounted_devices(device):
        if device.get("mountpoint"):
            mounted_devices.append(
                device.get("path")
            )

        for child in device.get("children", []) or []:
            collect_mounted_devices(child)

    collect_mounted_devices(selected_device)

    for mounted_device in mounted_devices:
        if not mounted_device:
            continue

        try:
            subprocess.run(
                [
                    "udisksctl",
                    "unmount",
                    "-b",
                    mounted_device,
                ],
                check=True,
                capture_output=True,
                text=True,
            )

        except subprocess.CalledProcessError as e:
            error = (
                e.stderr.strip()
                or e.stdout.strip()
                or str(e)
            )

            raise RuntimeError(
                f"Could not unmount {mounted_device}: "
                f"{error}"
            ) from e

    # Re-read the device after unmounting and verify that
    # nothing on the selected USB remains mounted.
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

    if selected_device.get("mounted"):
        raise ValueError(
            "The selected device is still mounted. "
            "It cannot be initialized safely."
        )

    if selected_device.get("children_mounted"):
        raise ValueError(
            "A partition on the selected device is still mounted. "
            "It cannot be initialized safely."
        )


    async def format_device():
        bus = await MessageBus(
            bus_type=BusType.SYSTEM
        ).connect()

        try:
            object_path = device_to_udisks_object(
                device_path
            )

            introspection = await bus.introspect(
                UDISKS2_SERVICE,
                object_path,
            )

            proxy = bus.get_proxy_object(
                UDISKS2_SERVICE,
                object_path,
                introspection,
            )

            block = proxy.get_interface(
                UDISKS2_BLOCK_INTERFACE
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

            try:
                await block.call_format(
                    "ext4",
                    options,
                )

            except Exception as e:
                error = str(e)

                raise RuntimeError(
                    "UDisks2 could not initialize the device: "
                    + error
                ) from e

        finally:
            bus.disconnect()

    asyncio.run(
        format_device()
    )

    # Explicit success result.
    #
    # The previous implementation returned None after successful
    # initialization, which can cause GUI code to interpret success
    # as failure.
    return True


def _get_lsblk_data():
    """Return lsblk JSON data."""

    result = subprocess.run(
        [
            "lsblk",
            "-J",
            "-o",
            (
                "NAME,PATH,SIZE,TYPE,RM,TRAN,MOUNTPOINT,"
                "MODEL,VENDOR,SERIAL,FSTYPE,LABEL"
            ),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return json.loads(result.stdout)


def _device_has_mounted_child(device):
    """Return True if any child partition/filesystem is mounted."""

    for child in device.get("children", []) or []:
        if child.get("mountpoint"):
            return True

        if _device_has_mounted_child(child):
            return True

    return False


def _device_has_mount(device):
    """Return True if the device itself has a mountpoint."""

    if device.get("mountpoint"):
        return True

    return _device_has_mounted_child(device)


def _flatten_blockdevices(devices):
    """Flatten lsblk's nested block-device tree."""

    result = []

    for device in devices:
        result.append(device)

        children = device.get("children", []) or []

        result.extend(
            _flatten_blockdevices(children)
        )

    return result


def find_removable_storage_devices():
    """
    Return removable USB disks suitable for initialization.

    Includes device identification information so the GUI can show
    the user exactly which physical device is going to be erased.
    """

    if not IS_LINUX:
        return []

    try:
        data = _get_lsblk_data()

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

        children = device.get("children", []) or []

        devices.append(
            {
                "name": device.get("name"),
                "path": device.get("path"),
                "size": device.get("size"),
                "model": (device.get("model") or "").strip(),
                "vendor": (device.get("vendor") or "").strip(),
                "serial": (device.get("serial") or "").strip(),
                "transport": device.get("tran"),
                "removable": bool(device.get("rm")),
                "mountpoint": device.get("mountpoint"),
                "mounted": _device_has_mount(device),
                "children_mounted": _device_has_mounted_child(
                    device
                ),
                "children": children,
            }
        )

    return devices


def get_device_info(device_path):
    """
    Return identification information for a specific removable
    storage device.
    """

    for device in find_removable_storage_devices():
        if device["path"] == device_path:
            return device

    return None


def format_device_description(device):
    """Create a human-readable description of a storage device."""

    if not device:
        return "Unknown device"

    lines = []

    path = device.get("path")
    if path:
        lines.append(f"Device: {path}")

    model = device.get("model")
    if model:
        lines.append(f"Model: {model}")

    vendor = device.get("vendor")
    if vendor:
        lines.append(f"Vendor: {vendor}")

    size = device.get("size")
    if size:
        lines.append(f"Size: {size}")

    serial = device.get("serial")
    if serial:
        lines.append(f"Serial: {serial}")

    transport = device.get("transport")
    if transport:
        lines.append(f"Transport: {transport.upper()}")

    if device.get("removable"):
        lines.append("Removable: Yes")

    if device.get("mounted"):
        lines.append("Mounted: Yes")
    else:
        lines.append("Mounted: No")

    return "\n".join(lines)


def find_luks_device():
    """Find the removable USB device containing the LUKS container."""

    try:
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

    except Exception:
        return None

    for line in result.stdout.splitlines():
        fields = line.split()

        if len(fields) != 5:
            continue

        (
            device,
            device_type,
            filesystem,
            removable,
            transport,
        ) = fields

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


def find_filesystem_device():
    """
    Find the filesystem device inside the unlocked LUKS container.
    """

    luks_device = find_luks_device()

    if luks_device is None:
        return None

    try:
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

    except Exception:
        return None

    for line in result.stdout.splitlines():
        fields = line.split()

        if len(fields) != 4:
            continue

        (
            device,
            device_type,
            filesystem,
            parent_name,
        ) = fields

        if device_type != "crypt":
            continue

        if filesystem != "ext4":
            continue

        if parent_name == luks_device:
            return device

    return None


def find_mount_path(device):
    result = subprocess.run(
        [
            "findmnt",
            "-n",
            "-o",
            "TARGET",
            device,
        ],
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
        raise RuntimeError(
            "Encrypted storage is not unlocked."
        )

    mount_path = find_mount_path(device)

    if mount_path is None:
        raise RuntimeError(
            "Encrypted storage is not mounted."
        )

    return os.path.join(
        mount_path,
        STORAGE_DIRECTORY,
    )


def ensure_storage_layout():
    """Create the signer storage directory if it does not exist."""

    storage_root = get_storage_root()

    os.makedirs(
        storage_root,
        mode=0o700,
        exist_ok=True,
    )

    return storage_root


def device_to_udisks_object(device):
    if not device.startswith("/dev/"):
        raise ValueError(
            f"Invalid device path: {device}"
        )

    device_name = device[5:]

    object_name = device_name.replace(
        "-",
        "_2d",
    )

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
        raise RuntimeError(
            "LUKS device not found."
        )

    object_path = device_to_udisks_object(
        device
    )

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
        raise RuntimeError(
            "Unlocked filesystem not found."
        )

    existing_mount = find_mount_path(
        device
    )

    if existing_mount is not None:
        return existing_mount

    result = subprocess.run(
        [
            "udisksctl",
            "mount",
            "-b",
            device,
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    output = result.stdout.strip()
    marker = " at "

    if marker not in output:
        raise RuntimeError(
            f"Could not determine mount path: {output}"
        )

    return output.split(
        marker,
        1,
    )[1].strip()


def unmount():
    device = find_filesystem_device()

    if device is None:
        return False

    try:
        result = subprocess.run(
            [
                "findmnt",
                "-rn",
                "-S",
                device,
                "-o",
                "TARGET",
            ],
            text=True,
            capture_output=True,
            check=True,
        )

    except subprocess.CalledProcessError:
        return False

    mount_paths = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    if not mount_paths:
        return False

    subprocess.run(
        [
            "udisksctl",
            "unmount",
            "-b",
            device,
        ],
        check=True,
        text=True,
    )

    try:
        result = subprocess.run(
            [
                "findmnt",
                "-rn",
                "-S",
                device,
                "-o",
                "TARGET",
            ],
            text=True,
            capture_output=True,
            check=True,
        )

    except subprocess.CalledProcessError:
        return True

    remaining_mounts = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    if remaining_mounts:
        raise RuntimeError(
            "Filesystem is still mounted at: "
            + ", ".join(remaining_mounts)
        )

    return True


def lock():
    luks_device = find_luks_device()

    if luks_device is None:
        return False

    filesystem_device = find_filesystem_device()

    if filesystem_device is None:
        return False

    existing_mount = find_mount_path(
        filesystem_device
    )

    if existing_mount is not None:
        raise RuntimeError(
            "Cannot lock LUKS device while filesystem "
            f"is mounted at {existing_mount}."
        )

    subprocess.run(
        [
            "udisksctl",
            "lock",
            "-b",
            luks_device,
        ],
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
