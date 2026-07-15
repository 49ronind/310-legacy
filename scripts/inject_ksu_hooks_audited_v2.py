#!/usr/bin/env python3
from pathlib import Path
import argparse
import sys

ROOT = Path('.')

DECL_PATCHES = [
    {
        'name': 'exec_decl',
        'file': 'fs/exec.c',
        'anchor_line': '#include <linux/syscalls.h>',
        'mode': 'after',
        'declaration': 'extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);',
        'insert_block': '#ifdef CONFIG_KSU
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);
#endif
',
    },
    {
        'name': 'open_decl',
        'file': 'fs/open.c',
        'anchor_line': '#include <linux/syscalls.h>',
        'mode': 'after',
        'declaration': 'extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *flags);',
        'insert_block': '#ifdef CONFIG_KSU
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *flags);
#endif
',
    },
    {
        'name': 'stat_decl',
        'file': 'fs/stat.c',
        'anchor_line': '#include <linux/syscalls.h>',
        'mode': 'after',
        'declaration': 'extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);',
        'insert_block': '#ifdef CONFIG_KSU
extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
#endif
',
    },
    {
        'name': 'reboot_decl',
        'file': 'kernel/reboot.c',
        'anchor_line': '#include <linux/syscalls.h>',
        'mode': 'after',
        'declaration': 'extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);',
        'insert_block': '#ifdef CONFIG_KSU
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif
',
    },
    {
        'name': 'input_decl',
        'file': 'drivers/input/input.c',
        'anchor_line': '#include <linux/input/mt.h>',
        'mode': 'after',
        'declaration': 'extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);',
        'insert_block': '#ifdef CONFIG_KSU
extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);
#endif
',
    },
]

FUNC_PATCHES = [
    {
        'name': 'exec',
        'file': 'fs/exec.c',
        'scope_start': 'static int do_execveat_common(',
        'anchor_line': 'int retval;',
        'mode': 'after',
        'duplicate_marker': 'ksu_handle_execveat(',
        'insert_block': '#ifdef CONFIG_KSU
\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
#endif
',
    },
    {
        'name': 'open',
        'file': 'fs/open.c',
        'scope_start': 'SYSCALL_DEFINE3(faccessat,',
        'anchor_line': 'unsigned int lookup_flags = LOOKUP_FOLLOW;',
        'mode': 'after',
        'duplicate_marker': 'ksu_handle_faccessat(',
        'insert_block': '#ifdef CONFIG_KSU
\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif
',
    },
    {
        'name': 'read',
        'file': 'fs/read_write.c',
        'scope_start': 'vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)',
        'anchor_line': 'if (!(file->f_mode & FMODE_READ))',
        'mode': 'after',
        'duplicate_marker': 'ksu_handle_vfs_read(',
        'insert_block': '#ifdef CONFIG_KSU
\tksu_handle_vfs_read(&file, &buf, &count, &pos);
#endif
',
    },
    {
        'name': 'stat',
        'file': 'fs/stat.c',
        'scope_start': 'int vfs_statx(',
        'anchor_line': 'struct path path;',
        'mode': 'after',
        'duplicate_marker': 'ksu_handle_stat(',
        'insert_block': '#ifdef CONFIG_KSU
\tksu_handle_stat(&dfd, &filename, &flags);
#endif
',
    },
    {
        'name': 'reboot_call',
        'file': 'kernel/reboot.c',
        'scope_start': 'SYSCALL_DEFINE4(reboot,',
        'anchor_line': 'int ret = 0;',
        'mode': 'after',
        'duplicate_marker': 'ksu_handle_sys_reboot(',
        'insert_block': '#ifdef CONFIG_KSU
\t{
\t\tint ksu_ret = ksu_handle_sys_reboot(magic1, magic2, cmd, (void __user **)&arg);
\t\tif (ksu_ret) return ksu_ret;
\t}
#endif
',
    },
    {
        'name': 'input',
        'file': 'drivers/input/input.c',
        'scope_start': 'static void input_handle_event(',
        'anchor_line': 'int disposition = input_get_disposition(dev, type, code, &value);',
        'mode': 'after',
        'duplicate_marker': 'ksu_handle_input_handle_event(',
        'insert_block': '#ifdef CONFIG_KSU
\tksu_handle_input_handle_event(&type, &code, &value);
#endif
',
    },
]


def preview(text, needle, radius=5):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if needle in line:
            start = max(0, i - radius)
            end = min(len(lines), i + radius + 1)
            return '
'.join(f'{n+1}: {lines[n]}' for n in range(start, end))
    return '(preview unavailable)'


def insert_once(text, anchor_line, block, mode):
    idx = text.find(anchor_line)
    if idx < 0:
        return None
    line_end = text.find('
', idx)
    if line_end < 0:
        line_end = len(text)
    insert_at = line_end + 1 if mode == 'after' and line_end < len(text) else idx
    return text[:insert_at] + block + text[insert_at:]


def find_scope(text, start_marker):
    start = text.find(start_marker)
    if start < 0:
        return None, None
    brace = text.find('{', start)
    if brace < 0:
        return None, None
    depth = 0
    for i in range(brace, len(text)):
        c = text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return start, i + 1
    return None, None


def patch_decl(patch, check_only=False):
    path = ROOT / patch['file']
    text = path.read_text()
    if patch['declaration'] in text:
        print(f"[+] [{patch['name']}] Declaration already present")
        return True
    new_text = insert_once(text, patch['anchor_line'], patch['insert_block'], patch['mode'])
    if new_text is None:
        print(f"[-] [{patch['name']}] Anchor not found: {patch['anchor_line']}")
        return False
    if check_only:
        print(f"[+] [{patch['name']}] Dry-run declaration preview")
        print(preview(new_text, patch['declaration']))
        return True
    path.write_text(new_text)
    print(f"[+] [{patch['name']}] Patched and verified in {patch['file']}")
    print(preview(new_text, patch['declaration']))
    return True


def patch_func(patch, check_only=False):
    path = ROOT / patch['file']
    text = path.read_text()
    start, end = find_scope(text, patch['scope_start'])
    if start is None:
        print(f"[-] [{patch['name']}] Scope start not found: {patch['scope_start']}")
        return False
    scoped = text[start:end]
    marker = patch.get('duplicate_marker')
    if marker and marker in scoped:
        print(f"[+] [{patch['name']}] Handler already present in scoped function, skipping")
        print(preview(scoped, marker))
        return True
    new_scoped = insert_once(scoped, patch['anchor_line'], patch['insert_block'], patch['mode'])
    if new_scoped is None:
        print(f"[-] [{patch['name']}] Scoped anchor not found: {patch['anchor_line']}")
        return False
    if check_only:
        line = patch['insert_block'].splitlines()[1].strip()
        print(f"[+] [{patch['name']}] Dry-run function patch preview")
        print(preview(new_scoped, line))
        return True
    new_text = text[:start] + new_scoped + text[end:]
    path.write_text(new_text)
    line = patch['insert_block'].splitlines()[1].strip()
    print(f"[+] [{patch['name']}] Patched and verified in {patch['file']}")
    print(preview(new_scoped, line))
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args()

    print('[+] Static audit passed')
    print('[*] Applying declaration patches')
    ok = True
    for patch in DECL_PATCHES:
        ok &= patch_decl(patch, check_only=args.check)

    print('[*] Applying function hook patches')
    for patch in FUNC_PATCHES:
        ok &= patch_func(patch, check_only=args.check)

    if not ok:
        sys.exit(1)
    print('[+] All patch operations completed')


if __name__ == '__main__':
    main()
