#!/usr/bin/env python3
from pathlib import Path
import argparse
import sys

ROOT = Path('.')
TARGET = ROOT / 'fs/namespace.c'

INSERT_BLOCK = r'''
static int can_umount(const struct path *path, int flags)
{
\tstruct mount *mnt = real_mount(path->mnt);

\tif (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
\t\treturn -EINVAL;
\tif (!may_mount())
\t\treturn -EPERM;
\tif (path->dentry != path->mnt->mnt_root)
\t\treturn -EINVAL;
\tif (!check_mnt(mnt))
\t\treturn -EINVAL;
\tif (mnt->mnt.mnt_flags & MNT_LOCKED) /* Check optimistically */
\t\treturn -EINVAL;
\tif (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))
\t\treturn -EPERM;
\treturn 0;
}

int path_umount(struct path *path, int flags)
{
\tstruct mount *mnt = real_mount(path->mnt);
\tint ret;

\tret = can_umount(path, flags);
\tif (!ret)
\t\tret = do_umount(mnt, flags);

\t/* we mustn't call path_put() as that would clear mnt_expiry_mark */
\tdput(path->dentry);
\tmntput_no_expire(mnt);
\treturn ret;
}

'''.lstrip('
')

DUPLICATE_MARKERS = [
    'static int can_umount(const struct path *path, int flags)',
    'int path_umount(struct path *path, int flags)',
]

ANCHORS = [
    '
#endif

/*
 * Now umount can handle mount points as well as block devices.
',
    '
#endif

/*
  * Now umount can handle mount points as well as block devices.
',
]

def preview(text, needle, radius=6):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if needle in line:
            start = max(0, i - radius)
            end = min(len(lines), i + radius + 1)
            return '
'.join(f'{n + 1}: {lines[n]}' for n in range(start, end))
    return '(preview unavailable)'

def already_present(text):
    return all(marker in text for marker in DUPLICATE_MARKERS)

def insert_before_anchor(text, anchor, block):
    idx = text.find(anchor)
    if idx < 0:
        return None
    return text[:idx] + block + text[idx:]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true', help='Preview only; do not write files')
    args = parser.parse_args()

    if not TARGET.is_file():
        print(f'[-] File not found: {TARGET}')
        sys.exit(1)

    text = TARGET.read_text()

    if already_present(text):
        print('[+] path_umount backport already present, skipping')
        print(preview(text, 'int path_umount(struct path *path, int flags)'))
        return
