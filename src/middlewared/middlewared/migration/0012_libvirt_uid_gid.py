import os
import subprocess

from middlewared.plugins.vm.utils import LIBVIRT_QEMU_UID, LIBVIRT_QEMU_GID, SYSTEM_NVRAM_FOLDER_PATH


def migrate(middleware):
    paths = []
    for device in middleware.call_sync('vm.device.query', [['dtype', 'in', ['CDROM', 'RAW']]]):
        paths.append(device['attributes']['path'])

    subprocess.run(['chown', f'{LIBVIRT_QEMU_UID}:{LIBVIRT_QEMU_GID}', *paths])
