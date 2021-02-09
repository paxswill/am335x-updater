# **WARNING!**
This tool is still under development, and (probably) doesn't work. It mucks
around with a device's firmware, and can prevent a device from booting if the
tool doesn't work correctly.

# am335x-updater

This is a script for updating the bootloaders on TI AM335x devices (like
BeagleBones). It handles both the SPL (aka MLO) and full U-Boot files that are
placed directly on a block device (as opposed to the boot method that allows
files to be put on the first FAT partition).

# Requirements:
The device tree compiler (`dtc`) needs to be accessible, as well as pyYAML.
You can install both on Debian-based systems with `sudo apt update && sudo apt
install -y device-tree-compiler python3-yaml`.

At the moment the script requires Python 3.8, but I'm working to add 3.7
compatibility soon.