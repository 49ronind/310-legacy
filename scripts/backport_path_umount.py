#!/usr/bin/env python3
from pathlib import Path
import argparse
import sys

ROOT = Path('.')
TARGET = ROOT / 'fs/namespace.c'

INSERT_BLOCK = """
static int can_umount(const struct path *path, int flags)
{
	struct mount *mnt = real_mount(path->mnt);

	if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
		return -EINVAL;
	if (!may_mount())
		return -EPERM;
	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;
	if (!check_mnt(mnt))
		return -EINVAL;
	if (mnt->mnt.mnt_flags & MNT_LOCKED) /* Check optimistically */
		return -EINVAL;
	if (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

int path_umount(struct path *path, int flags)
{
	struct mount *mnt = real_mount(path->mnt);
	int ret;

	ret = can_umount(path, flags);
	if (!ret)
		ret = do_umount(mnt, flags);

	/* we mustn't call path_put() as that would clear mnt_expiry_mark */
	dput(path->dentry);
	mntput_no_expire(mnt);
	return ret;
}

""".lstrip('\n')

DUPLICATE_MARKERS = [
    'static int can_umount(const struct path *path, int flags)',
    'int path_umount(struct path *path, int flags)',
]

ANCHORS = [
    '
/*
 * Now umount can handle mount points as well as block devices.
',
    '
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
            return '\n'.join(f'{n + 1}: {lines[n]}' for n in range(start, end))
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

    new_text = None
    matched_anchor = None
    for anchor in ANCHORS:
        new_text = insert_before_anchor(text, anchor, INSERT_BLOCK)
        if new_text is not None:
            matched_anchor = anchor
            break

    if new_text is None:
        print('[-] No safe anchor found in fs/namespace.c')
        print('[-] Expected one of the known anchors before the umount comment block')
        sys.exit(1)

    if args.check:
        print('[+] Dry-run passed for path_umount backport')
        print(f'[+] Matched anchor: {matched_anchor.strip().splitlines()[-1]}')
        print(preview(new_text, 'int path_umount(struct path *path, int flags)'))
        return

    TARGET.write_text(new_text)

    verify_text = TARGET.read_text()
    if not already_present(verify_text):
        print('[-] Verification failed after write')
        sys.exit(1)

    print('[+] path_umount backport applied successfully')
    print(preview(verify_text, 'int path_umount(struct path *path, int flags)'))


if __name__ == '__main__':
    main()
