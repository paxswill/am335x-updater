#!/usr/bin/env python3

from __future__ import annotations

import argparse
import contextlib
import enum
import functools
import hashlib
import io
import logging
import math
import os
import os.path
import re
import struct
import subprocess
import sys
import typing

import yaml


# Using a slightly different name for the logger to keep it Python-safe
log = logging.getLogger("am335x_updater")
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s: %(message)s",
    stream=sys.stderr,
)


DEFAULT_SECTOR_SIZE = 512


def get_block_size(device: os.PathLike) -> int:
    """Look up the device block size (in bytes) in sysfs.

    This value is also used as the sector size in this script. If there's an
    error in looking up the4 value, 512 is used.
    """
    device_path: typing.Union[str, bytes]
    if isinstance(device, os.PathLike):
        device_path = device.__fspath__()
    else:
        device_path = device
    if isinstance(device_path, str):
        device_regex = r"(?:/dev/)?(\w+)"
    elif isinstance(device_path, bytes):
        device_regex = rb"(?:/dev/)?(\w+)"
    else:
        # This should never be reached, as the spec for os.PathLike is that
        # __fspath__() returns either str or bytes.
        raise RuntimeError(
            "__fspath__() returned something other than str or bytes"
        )
    match = re.match(device_regex, device_path)
    # The only way this assertion should fail is if the string given includes
    # whitespace, or has no characters at all.
    assert match is not None
    device_name = match.group(1)
    block_size_path = f"/sys/class/block/{device_name}/queue/logical_block_size"
    if not os.path.exists(block_size_path):
        log.warning(
            "'%s' is not a block device, defaulting to %d-byte sectors",
            device,
            DEFAULT_SECTOR_SIZE
        )
        log.debug("'%s' does not exist", block_size_path)
        return DEFAULT_SECTOR_SIZE
    with open(block_size_path, "r") as sys_block_size:
        return int(sys_block_size.read().strip())


def find_mbr_first_partition(
    stream: io.BinaryIO,
    sector_size: int = DEFAULT_SECTOR_SIZE,
) -> typing.Union[int, None]:
    """Find the offset of the first partition in an MBR.

    The given stream is assumed to be at offset 0 of a raw block device. If
    there is a valid MBR, the four primary partition entries are examined, and
    the entry with the lowest starting sector is found. The value of the
    starting sector is then multipled by 512 to get the byte offset of the first
    partition.

    If there is not a valid MBR, or no partitions are found, `None` is returned.
    """
    starting_offset = stream.tell()
    if starting_offset != 0:
        log.warning(
            "The starting offset of %s is not 0! (actual value is %#x)",
            stream,
            starting_offset,
        )
    # Skip forward to the boot signature and check that first
    MBR_BOOT_SIG_OFFSET = 0x1fe
    # Because there's a mix of absolute and relative seeking in this function,
    # all seek() calls in it are explicit in which kind they are.
    stream.seek(MBR_BOOT_SIG_OFFSET, os.SEEK_CUR)
    boot_sig_buf = stream.read(2)
    boot_sig = struct.unpack("<2B", boot_sig_buf)
    if boot_sig != (0x55, 0xaa):
        log.warning(
            "Invalid boot signature (%s) found.",
            ", ".join(f"{n:#x}" for n in boot_sig)
        )
        return None
    stream.seek(starting_offset, os.SEEK_SET)
    # Partition entries start at 0x1be, and are 16 bytes long. They follow one
    # after another four times, for a total of 64 bytes
    MBR_FIRST_PART_ENTRY = 0x1be
    stream.seek(MBR_FIRST_PART_ENTRY, os.SEEK_CUR)
    # Each partition entry has:
    # * flags (1 byte)
    # * CHS start (3 bytes, packed format)
    # * partition type (1 byte)
    # * CHS end (3 bytes, packed format)
    # * LBA start (4 bytes, unsigned int)
    # * Sector count (4 bytes, unsigned int)
    #
    # All values are little-endian. The CHS values are packed, but we're only
    # interested in the LBA of the starting sector, so I don't care about the
    # CHS values and don't need to unpack them.
    mbr_entry_format = "<B3sB3s2I"
    lowest_starting_sector = 0xffffffff
    for i in range(4):
        entry_buf = stream.read(16)
        # All zeros is an empty entry which we can skip
        if not any(entry_buf):
            continue
        partition_entry = struct.unpack(mbr_entry_format, entry_buf)
        log.debug(
            "Partition entry %d values: %s",
            i,
            # Output the integers as 0xF00 and the bytes in hex, but without
            # any prefix.
            tuple(
                n.hex(" ") if isinstance(n, bytes) else f"{n:#x}"
                for n in partition_entry
            )
        )
        if partition_entry[4] < lowest_starting_sector:
            lowest_starting_sector = partition_entry[4]
            log.debug(
                "New lowest starting sector of %s (%#x)",
                lowest_starting_sector,
                lowest_starting_sector,
            )
    return sector_size * lowest_starting_sector


class InvalidFirmwareImage(Exception):
    """The base exception for when a firmware image is invalid."""
    pass


def get_mlo_toc_size(
    stream: io.BinaryIO
) -> int:
    """Determine the size of a possible MLO image.

    The given stream is checked starting from its current position. If a valid
    TOC is found there, the total size in bytes of the MLO image is returned. If
    the data found is not an MLO image, `InvalidFirmwareImage` is raised.
    """
    starting_offset = stream.tell()
    # Instead of manually verifying each field, I'm just going to hash the
    # entire TOC. The contents are fixed, even though a quick read of the
    # documentation looks like it might be used in other places where the
    # content could vary.
    TOC_LEN = 512
    toc_hasher = hashlib.sha256(stream.read(TOC_LEN))
    toc_hex = toc_hasher.hexdigest()
    log.debug("TOC hash for %s at %#x: %s", stream, starting_offset, toc_hex)
    expected_hash = (
        "21a542439d495f829f448325a75a2a377bf84c107751fe77a0aeb321d1e23868"
    ) 
    if toc_hex != expected_hash:
        msg = (
            f"TOC hash at {stream}, offset {starting_offset:#x} did not match",
        )
        raise InvalidFirmwareImage(msg)
    else:
        log.debug(
            "TOC hash at %s, offset %#x matched",
            stream,
            starting_offset
        )
    # Read the size of the image right after the TOC. The first 4 bytes are a
    # little-endian unsigned int representing the size of the image in bytes.
    # The size does not include the TOC size.
    # Relying on the read position of stream being where it was left from
    # reading the TOC.
    image_len_buf = stream.read(4)
    image_len = struct.unpack_from("<I", image_len_buf)[0]
    return image_len + TOC_LEN


class InvalidUBootImage(InvalidFirmwareImage):
    """Exception for when a U-Boot image is of the wrong type."""
    pass


def get_u_boot_legacy_size(
    stream: io.BinaryIO,
) -> int:
    """Determine the size of a possible U-Boot legacy image.

    The given stream is checked starting from its current position. If a valid
    U-Boot legacy image is found there, the total size in bytes of the image is
    returned. If no image is found, an `InvalidFirmwareImage` exception will be raised.
    """
    U_BOOT_HEADER_LEN = 64
    header_buf = stream.read(U_BOOT_HEADER_LEN)
    # This format spec is based on the U-Boot sources, specifically the
    # definition of image_header_t in include/image.h
    header_format = ">7I4B32s"
    parsed_header = struct.unpack(header_format, header_buf)
    # The fields we care about are the magic number (index 0), image data size
    # (index 3), operating system (index 7), and image type (index 9).
    UBOOT_LEGACY_MAGIC = 0x27051956
    if parsed_header[0] != UBOOT_LEGACY_MAGIC:
        raise InvalidFirmwareImage("Incorrect legacy U-Boot magic number")
    # OS code 17 is the code for a U-Boot firmware image.
    if parsed_header[7] != 17:
        raise InvalidUBootImage(
            "U-Boot image found, but with the incorrect OS (OS type "
            f"{parsed_header[7]})"
        )
    # Image type 5 is a firmware image, which is what is used for U-Boot images.
    if parsed_header[9] != 5:
        raise InvalidUBootImage(
            "U-Boot image found, but with the incorrect image type (image type "
            f"{parsed_header[9]})"
        )
    return parsed_header[3] + U_BOOT_HEADER_LEN


def align_up(n: int, align_to: int) -> int:
    """Return `n`, rounded up to `align_to`."""
    return align_to * math.ceil(n / align_to)


def get_u_boot_fit_size(
    stream: io.BinaryIO,
) -> int:
    """Determine the size of a possible U-Boot FIT image.

    The given stream is checked starting from its current position. If a valid
    U-Boot FIT image is found there, the total size in bytes of the image is
    returned. If no image is found, an `InvalidFirmwareImage` exception will be raised.
    """
    starting_offset = stream.tell()
    # The first 8 bytes of a flattened device tree (FDT) are a magic number, and
    # the total size of the FDT.
    buf = stream.read(8)
    magic, fdt_len = struct.unpack(">2I", buf)
    if magic != 0xd00dfeed:
        raise InvalidFirmwareImage(
            f"Magic number for {stream} at {starting_offset:#x} does not match"
            " for an FDT"
        )
    # Extract the FDT from the device (and only the FDT, which we can do because
    # the size is now known). Feed it into dtc to decompile it, then convert the
    # DTS to YAML for easier parsing.
    stream.seek(starting_offset, os.SEEK_SET)
    read_pipe, write_pipe = os.pipe()
    # Fork so we can have a process feed the data in to the pipe.
    if os.fork() != 0:
        os.close(write_pipe)
    else:
        os.close(read_pipe)
        fdt_data = stream.read(fdt_len)
        os.write(write_pipe, fdt_data)
        os.close(write_pipe)
        sys.exit()
    decompile = subprocess.Popen(
        ["/usr/bin/dtc", "-I", "dtb", "-O", "dts", "-o", "-", "-"],
        stdin=read_pipe,
        stdout=subprocess.PIPE,
        close_fds=True,
    )
    yaml_convert = subprocess.Popen(
        ["/usr/bin/dtc", "-I", "dts", "-O", "yaml", "-o", "-", "-"],
        stdin=decompile.stdout,
        stdout=subprocess.PIPE,
    )
    fit_yaml = yaml.safe_load_all(yaml_convert.communicate()[0])
    # FIT uses the DTS format, with a couple of differences. We only care about
    # the "images" nodes. To figure out the size of the FIT image, we look at
    # the "data-size" and "data-offset" properties of the image nodes.
    try:
        # We only care about the first document, and the first tree in that
        # document.
        images = next(iter(fit_yaml))[0]["images"]
        largest_offset = 0
        offset_size = 0
        uboot_image_found = False
        for image_data in images.values():
            # The data-[size,offset] properties have only one value
            image_offset = image_data["data-offset"][0][0]
            image_size = image_data["data-size"][0][0]
            # Wrap `None` in an list to emulate how DTS has almost everything as
            # a list.
            image_type = image_data.get("type", [None])[0]
            image_os = image_data.get("os", [None])[0]
            log.debug(
                # Stringifying image_type and image_os so that integers turn
                # into base-10 strings, and `None` turns into "None"
                "Found image with offset %#x, size %d, type %s, OS %s",
                image_offset,
                image_size,
                str(image_type),
                str(image_os),
            )
            if image_offset > largest_offset:
                largest_offset = image_offset
                offset_size = image_size
            if image_type == "firmware" and image_os == "u-boot":
                uboot_image_found = True
    except (KeyError, IndexError) as exc:
        raise InvalidFirmwareImage("Invalid access in FIT parsing") from exc
    if not uboot_image_found:
        raise InvalidUBootImage(
            "No U-Boot firmware sub-image contained within FIT image."
        )
    # The full size is now the FDT size + (the largest image offset + the size
    # of that image, rounded up to the nearest 4-byte boundary)
    extra_len = largest_offset + offset_size
    return align_up(fdt_len, 4) + align_up(extra_len, 4)


@functools.total_ordering
class ImageKind(enum.Enum):

    #: Called SPL images by U-Boot, and MLO in the AM335x Reference Manual.
    MLO = "MLO image"

    #: Covers both U-Boot legacy and FIT images.
    UBOOT = "U-Boot image"

    def __lt__(self, other):
        """Define an ordering for `ImageKind`.

        Because there's only two kinds of image, it's just "MLO before UBOOT".
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        # MLO before U-Boot
        return self is self.MLO and other is self.UBOOT


class FirmwareImage(object):
    """A combination of device, offset, image type, and image size."""

    #: The device name or this image was found on, or a path to a bootloader
    #: image file.
    device: os.PathLike

    #: The offset on the device that the image was found at.
    offset: int

    #: The kind of image it is.
    kind: ImageKind

    #: The size of the image.
    size: int

    @typing.overload
    def __init__(
        self,
        device: os.PathLike,
        offset: int,
        kind: ImageKind,
        size: int,
    ): ...

    @typing.overload
    def __init__(
        self,
        device: os.PathLike,
        kind: ImageKind,
    ): ...

    def __init__(self, *args, **kwargs):
        """Represent a firmware image.

        The source data for an image can either be a discrete file on a
        filesystem, or a range of bytes (defined as an offset and length) on a
        raw block device.
        """
        attr_names = ("device", "offset", "kind", "size")
        if len(args) == 4:
            for attr_name, arg in zip(attr_names, args):
                setattr(self, attr_name, arg)
        elif kwargs.keys() == set(attr_names):
            for attr_name in attr_names:
                setattr(self, attr_name, kwargs[attr_name])
        elif len(args) == 2:
            self.device, self.kind = args
            self.offset = 0
            stat = os.stat(self.device)
            self.size = stat.st_size
        elif kwargs.keys() == {"device", "kind"}:
            self.device = kwargs["device"]
            self.kind = kwargs["kind"]
            self.offset = 0
            stat = os.stat(self.device)
            self.size = stat.st_size
        else:
            raise ValueError()

    @functools.cached_property
    def hexdigest(self) -> str:
        """A secure hash of the data for this firmware image.

        Currently this is the SHA256 of the data.
        """
        with open(self.device, "rb") as device:
            device.seek(self.offset)
            hasher = hashlib.sha256(
                device.read(self.size)
            )
        return hasher.hexdigest()

    @property
    def path(self):
        """An alias for `device`.

        This is just to make it more logical to refer to firmware images that
        exist as files on a filesystem instead of byte ranges on an device.
        """
        return self.device

    def __eq__(self, other: FirmwareImage) -> bool:
        """Compare a firmware image to another firmware image.

        Only the `hexdigest` of both objects are compared.
        """
        if isinstance(other, FirmwareImage):
            return self.hexdigest == other.hexdigest
        else:
            return NotImplemented

    def __lt__(
        self,
        other: typing.Union[FirmwareImage, int]
    ) -> bool:
        if isinstance(other, FirmwareImage):
            return self.offset + self.size < other.offset
        elif isinstance(other, int):
            return self.offset + self.size < other
        else:
            return NotImplemented

    def __le__(
        self,
        other: typing.Union[FirmwareImage, int]
    ) -> bool:
        if isinstance(other, FirmwareImage):
            return self.offset + self.size <= other.offset
        elif isinstance(other, int):
            return self.offset + self.size <= other
        else:
            return NotImplemented

    def __gt__(
        self,
        other: typing.Union[FirmwareImage, int]
    ) -> bool:
        if isinstance(other, FirmwareImage):
            return self.offset + self.size > other.offset
        elif isinstance(other, int):
            return self.offset + self.size > other
        else:
            return NotImplemented

    def __ge__(
        self,
        other: typing.Union[FirmwareImage, int]
    ) -> bool:
        if isinstance(other, FirmwareImage):
            return self.offset + self.size >= other.offset
        elif isinstance(other, int):
            return self.offset + self.size >= other
        else:
            return NotImplemented

    def __matmul__(
        self,
        new_offset: typing.Union[int, FirmwareImage]
    ) -> FirmwareImage:
        """Return a copy of this object, but with a different `offset`."""
        if isinstance(new_offset, int):
            if new_offset < 0:
                raise ValueError(
                    f"The new offset ({new_offset}) must be greater than 0"
                )
        elif isinstance(new_offset, FirmwareImage):
            new_offset = new_offset.offset
        else:
            return NotImplemented
        return type(self)(self.device, new_offset, self.kind, self.size)

    def __repr__(self):
        # defining repr so that the size and offset are in hex
        return (
            f"{self.__class__.__name__}('{self.device}', {self.offset:#x}, "
            f"ImageKind.{self.kind.name}, {self.size:#x})"
        )


# Copy the FirmwareImage overlap docstring to the ordering dunder methods
_firmware_image_comparison_docstring = \
"""Compare the byte range of an image to an offset.

When ``other`` is an integer, the sum of ``self.offset`` and
``self.size`` is compared against ``other``. When ``other`` is another
`FirmwareImage`, the `offset` is taken, and then the comparison is done
as if an integer was given.

The intention is for this operation to be used to see if an image would
overlap aither another image, or a given offset.
"""
for method_name in ("__lt__", "__le__", "__gt__", "__ge__"):
    method = getattr(FirmwareImage, method_name)
    method.__doc__ = _firmware_image_comparison_docstring


def find_images(device_path: os.PathLike) -> typing.Collection[FirmwareImage]:
    """Find firmware images on a raw block device."""
    images = []
    image_finders = (
        get_mlo_toc_size,
        get_u_boot_legacy_size,
        get_u_boot_fit_size
    )
    with open(device_path, "rb") as device:
        for offset in (0, 0x20000, 0x40000, 0x60000):
            for get_size in image_finders:
                device.seek(offset)
                try:
                    image_size = get_size(device)
                except InvalidFirmwareImage as exc:
                    # Just log these exceptions, they're expected
                    log.debug("%s", exc)
                else:
                    if get_size is get_mlo_toc_size:
                        image_kind = ImageKind.MLO
                    else:
                        image_kind = ImageKind.UBOOT
                    images.append(FirmwareImage(
                        device_path,
                        offset,
                        image_kind,
                        image_size
                    ))
    return images


def compare_images(
    new_mlo: FirmwareImage,
    new_u_boot: FirmwareImage,
    device_paths: typing.Iterable[os.PathLike],
) -> typing.Sequence[FirmwareImage]:
    """Update BeagleBone Black/Green firmware.

    This handles both raw and FAT bootloader configurations (see section
    26.1.8.5 of the AM335x Reference Manual for more details).
    """
    # There are two possible MMC/SD devices on BeagleBones, mmcblk0 and 1, and
    # four possible locations for the MLO: 0, 0x20000, 0x40000, and 0x60000.
    # The full U-Boot image is then (possibly) at one of the later loader
    # locations.
    images_to_update = []
    for device_path in device_paths:
        sector_size = get_block_size(device_path)
        log.debug("Using %d-byte sectors for %s", sector_size, device_path)
        with open(device_path, "rb") as device:
            lowest_partition_start = find_mbr_first_partition(
                device, sector_size
            )
            # Just not handling the case where there's no MBR
            if lowest_partition_start is None:
                log.info(
                    "No MBR found on device '%s', skipping.",
                    device_path
                )
                continue
        images = find_images(device_path)
        if not images:
            log.debug("No firmware images found on device '%s'", device_path)
        for image in images:
            if image.offset == 0:
                # This error should not be hit
                log.error("%s would overlap the MBR", image)
                continue
            # "shift" the new image to the offset of the old image
            if image.kind is ImageKind.MLO:
                new_image = new_mlo
            elif image.kind is ImageKind.UBOOT:
                new_image = new_u_boot
            else:
                raise ValueError("Unknown image kind %s", image.kind)
            if new_image @ image >= lowest_partition_start:
                log.error(
                    "%s would overlap the partition starting at %#x",
                    image
                )
                continue
            # The equality operation *only* checks the sha256 hash of the data
            if new_image != image:
                log.info(
                    (
                        "New %(kind)s (%(path)s) does not match existing "
                        "%(kind)s on %(device_name)s at offset %(offset)#x"
                    ),
                    {
                        "kind": image.kind.value,
                        "path": new_image.path,
                        "device_name": device_path,
                        "offset": image.offset,
                    }
                )
                log.debug(
                    "%-20s: %s",
                    "New image hash",
                    new_image.hexdigest
                )
                log.debug(
                    "%-20s: %s",
                    "Existing image hash",
                    image.hexdigest
                )
                images_to_update.append(image)
    return images_to_update


def copy_raw(
    source_image: FirmwareImage,
    target_image: FirmwareImage,
):
    """Copy the contents of one image over another image."""
    with open(source_image.device, "rb") as source:
        source.seek(source_image.offset)
        fd = os.open(target_image.device, os.O_WRONLY)
        try:
            os.set_blocking(fd, True)
            os.lseek(fd, target_image.offset, os.SEEK_SET)
            # And now we rely on sendfile() aligning things properly
            write_size = os.sendfile(
                fd,
                source.fileno(),
                None,
                source_image.size
            )
            assert write_size == source_image.size
        except OSError:
            # reraise it immediately; this except-clause is to satisfy the
            # grammar so we can have an else-clause
            raise
        else:
            os.fsync(fd)
        finally:
            os.close(fd)


class MainAction(enum.Enum):
    """The type of action to perform when invoked as a command."""

    #: Log which changes would be made, but don't change anything.
    DRY_RUN = enum.auto()

    #: Interactively confirm each change before making it.
    INTERACTIVE = enum.auto()

    #: Make all changes without prompting for confirmation.
    FORCE = enum.auto()


def update_raw_beaglebone(
    new_mlo_path: os.PathLike,
    new_u_boot_path: os.PathLike,
    devices: typing.Iterable[os.PathLike],
    action: MainAction,
) -> bool:
    """Update a raw MMC device with updated firmware images.

    The source images are checked that they are able to be used as boot images,
    then the given devices are searched for existing images. For any images
    found, they are compared against the appropriate source image (MLO images to
    MLO images, U-Boot to U-Boot). If the images on device are different, they
    are (optionally) overwritten with the source images. The partition table is
    also examined to ensure that the new images will not overlap with the
    beginning of the first partition.

    This function will raise `FileNotFoundError` for missing source files and
    `ValueError` when the given files are not the right kind of image.
    It returns a boolean for if there were outdated images present.
    """
    if not os.path.exists(new_mlo_path):
        raise FileNotFoundError(
            f"MLO file ({new_mlo_path}) does not exist."
        )
    if not os.path.exists(new_u_boot_path):
        raise FileNotFoundError(
            f"U-Boot file ({new_u_boot_path}) does not exist."
        )
    # Check that the files given are actually the appropriate kind of files.
    with open(new_mlo_path, "rb") as mlo_file:
        try:
            get_mlo_toc_size(mlo_file)
        except InvalidFirmwareImage as exc:
            log.debug("%s", exc)
            raise ValueError(
                f"{new_mlo_path} does not have a valid TOC"
            ) from exc
    with open(new_u_boot_path, "rb") as u_boot_file:
        for get_size in (get_u_boot_fit_size, get_u_boot_legacy_size):
            u_boot_file.seek(0)
            try:
                get_size(u_boot_file)
            except InvalidUBootImage as exc:
                log.debug("%s", exc)
                raise ValueError(
                    f"{new_u_boot_path} does not contain a U-Boot firmware"
                    " image"
                ) from exc
            except InvalidFirmwareImage as exc:
                log.debug("Not a U-Boot image because: %s", exc)
                pass
            else:
                break
        else:
            raise ValueError(f"{new_u_boot_path} is not a valid U-Boot image")
    new_mlo = FirmwareImage(new_mlo_path, ImageKind.MLO)
    new_u_boot = FirmwareImage(new_u_boot_path, ImageKind.UBOOT)
    new_images = {
        ImageKind.MLO: new_mlo,
        ImageKind.UBOOT: new_u_boot,
    }
    outdated_images = list(compare_images(new_mlo, new_u_boot, devices))
    # Sort the images by kind, then device, then by offset
    outdated_images.sort(key=lambda i: (i.kind, i.device, i.offset))
    for image in outdated_images:
        destination_message = (
            f"{image.kind.value} at {image.offset:#x} "
            f"({image.size} bytes) on {image.device}"
        )
        source_message = (
            f"{new_images[image.kind].path} "
            f"({new_images[image.kind].size} bytes)"
        )
        if action is MainAction.DRY_RUN:
            print(
                f"{destination_message} would be overwritten by "
                f"{source_message}"
            )
        elif action is MainAction.FORCE:
            print(
                f"{destination_message} will be overwritten with the contents "
                f"of {source_message}"
            )
            copy_raw(new_images[image.kind], image)
        elif action is MainAction.INTERACTIVE:
            response = input(
                f"Should {destination_message} be overwritten by "
                f"{source_message}? [y/N] "
            )
            cleaned_response = response.lower().strip()
            if cleaned_response not in ("y", "yes"):
                print("Skipping...")
            else:
                copy_raw(new_images[image.kind], image)
    return bool(outdated_images)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    # This is pulled into a separate function to keep main() at a mangeable
    # length.
    parser = argparse.ArgumentParser(
        description="Check and update AM335x MMC bootloaders",
        # TODO: add extra help describing the exit status
    )
    # Action arguments
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument(
        "--dry-run", "-n",
        action="store_const",
        const=MainAction.DRY_RUN,
        help=(
            "Print messages showing which installed bootloaders do match the"
            " bootloader files, with no changes actually written. This is the"
            " default when not run interactively."
        ),
        dest="action",
    )
    action_group.add_argument(
        "--interactive", "-i",
        action="store_const",
        const=MainAction.INTERACTIVE,
        help=(
            "Prompt for confirmation for every change. This is the default when"
            " run interactively."
        ),
        dest="action",
    )
    action_group.add_argument(
        "--force", "-f",
        action="store_const",
        const=MainAction.FORCE,
        help=(
            "Replace any installed bootloaders that do not match the given "
            "files without confirmation."
        ),
        dest="action",
    )
    parser.set_defaults(
        action=MainAction.INTERACTIVE if os.isatty(1) else MainAction.DRY_RUN
    )
    # Target selection arguments
    DEFAULT_MLO_PATH = "/usr/lib/u-boot/am335x_evm/MLO"
    parser.add_argument(
        "--mlo", "-m",
        action="store",
        help=f"Path to the MLO file to use (default: {DEFAULT_MLO_PATH}).",
        default=DEFAULT_MLO_PATH,
        metavar="/path/to/MLO",
    )
    DEFAULT_UBOOT_PATH = "/usr/lib/u-boot/am335x_evm/u-boot.img"
    parser.add_argument(
        "--uboot", "-u",
        action="store",
        help=f"Path to the U-Boot file to use (default: {DEFAULT_UBOOT_PATH}).",
        default=DEFAULT_UBOOT_PATH,
        metavar="/path/to/u-boot.img",
    )
    parser.add_argument(
        "--device", "-d",
        action="append",
        help=(
            "Specify which MMC devices to check. Can be specified multiple "
            "times. (default: /dev/mmcblk0 and /dev/mmcblk1, if present)."
        ),
        default=list(filter(
            os.path.exists,
            ("/dev/mmcblk0", "/dev/mmcblk1")
        )),
        dest="devices",
    )
    # Logging arguments
    logging_group = parser.add_mutually_exclusive_group()
    logging_group.add_argument(
        "--verbose", "-v",
        action="count",
        help=(
            "Increase logging verbosity. May be given more than once to "
            "further increase verbosity."
        ),
        default=0,
        dest="log_level"
    )
    logging_group.add_argument(
        "--quiet", "-q",
        action="store_const",
        const=-1,
        help="Suppress all output.",
        dest="log_level",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    # Update the log level first
    log_levels = {
        -1: logging.CRITICAL,
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
    }
    log.setLevel(log_levels.get(
        # Clamp the value to a max of 2
        min(2, args.log_level),
        # If all else fails, give a default
        logging.WARNING
    ))
    # We need root to access block devices directly. Do this check after parsing
    # args so that the help message can be printed as a normal user.
    if os.geteuid() != 0:
        log.error("This program must be run as root.")
        sys.exit(-1)
    # This only makes sense to run on AM335x devices
    FDT_MODEL_PATH = "/proc/device-tree/model"
    if not os.path.exists(FDT_MODEL_PATH):
        log.error(
            "This device does not have a device tree, and can't be an "
            "AM335x device."
        )
        sys.exit(-1)
    with open(FDT_MODEL_PATH, "r") as model:
        model_name = model.read().lower()
        if "am335x" not in model_name:
            log.error("This does not appear to be an AM335x device.")
            sys.exit(-1)
    try:
        bootloader_difference = update_raw_beaglebone(
            args.mlo,
            args.uboot,
            args.devices,
            args.action,
        )
    except (ValueError, FileNotFoundError) as exc:
        log.error("%s", exc)
        sys.exit(-1)
    except KeyboardInterrupt:
        sys.exit(-1)
    if bootloader_difference:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()