import os
import sys
import argparse

PATCHES = [
    {
        "name": "exec",
        "filepath": "fs/exec.c",
        "func_sig": "do_execveat_common(",
        "anchor_line": "int retval;",
        "mode": "after",
        "hook_code": r'''#ifdef CONFIG_KSU
\textern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);
\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
#endif''',
    },
    {
        "name": "open",
        "filepath": "fs/open.c",
        "func_sig": "faccessat(",
        "anchor_line": "unsigned int lookup_flags",
        "mode": "after",
        "hook_code": r'''#ifdef CONFIG_KSU
\textern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *flags);
\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif''',
    },
    {
        "name": "read",
        "filepath": "fs/read_write.c",
        "func_sig": "vfs_read(",
        "anchor_line": "if (!(file->f_mode & FMODE_CAN_READ))",
        "mode": "before",
        "hook_code": r'''#ifdef CONFIG_KSU
\tksu_handle_vfs_read(&file, &buf, &count, &pos);
#endif''',
    },
    {
        "name": "stat",
        "filepath": "fs/stat.c",
        "func_sig": "vfs_statx(",
        "anchor_line": "struct path path;",
        "mode": "after",
        "hook_code": r'''#ifdef CONFIG_KSU
\textern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
\tksu_handle_stat(&dfd, &filename, &flags);
#endif''',
    },
    {
        "name": "reboot_decl",
        "filepath": "kernel/reboot.c",
        "func_sig": "SYSCALL_DEFINE4(reboot",
        "anchor_line": "SYSCALL_DEFINE4(reboot",
        "mode": "before",
        "hook_code": r'''#ifdef CONFIG_KSU
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif''',
    },
    {
        "name": "reboot_call",
        "filepath": "kernel/reboot.c",
        "func_sig": "SYSCALL_DEFINE4(reboot",
        "anchor_line": "int ret = 0;",
        "mode": "after",
        "hook_code": r'''#ifdef CONFIG_KSU
\t{
\t\tint ksu_ret = ksu_handle_sys_reboot(magic1, magic2, cmd, (void __user **)&arg);
\t\tif (ksu_ret) return ksu_ret;
\t}
#endif''',
    },
    {
        "name": "input",
        "filepath": "drivers/input/input.c",
        "func_sig": "input_handle_event(",
        "anchor_line": "input_get_disposition",
        "mode": "after",
        "hook_code": r'''#ifdef CONFIG_KSU
\textern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);
\tksu_handle_input_handle_event(&type, &code, &value);
#endif''',
    },
]


def fail(msg):
    print(f"[-] {msg}")
    sys.exit(1)


def info(msg):
    print(f"[*] {msg}")


def ok(msg):
    print(f"[+] {msg}")


def read_lines(path):
    if not os.path.exists(path):
        fail(f"File not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return f.readlines()


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def find_anchor(lines, func_sig, anchor_line):
    found_func = False
    for i, line in enumerate(lines):
        if func_sig in line:
            found_func = True
        if found_func and anchor_line in line:
            return i
    return None


def find_hook_near(lines, idx, hook_code, window=12):
    start = max(0, idx - window)
    end = min(len(lines), idx + window + 1)
    nearby = "".join(lines[start:end])
    return hook_code in nearby


def preview_around(lines, idx, radius=3):
    start = max(0, idx - radius)
    end = min(len(lines), idx + radius + 1)
    out = []
    for n in range(start, end):
        out.append(f"{n+1}: {lines[n].rstrip()}")
    return "\n".join(out)


def apply_patch(patch, dry_run=False):
    path = patch["filepath"]
    func_sig = patch["func_sig"]
    anchor_line = patch["anchor_line"]
    hook_code = patch["hook_code"]
    mode = patch["mode"]
    name = patch["name"]

    lines = read_lines(path)
    idx = find_anchor(lines, func_sig, anchor_line)

    if idx is None:
        fail(f"[{name}] Anchor not found in {path}: {anchor_line}")

    if find_hook_near(lines, idx, hook_code):
        ok(f"[{name}] Hook already present in {path}")
        print(preview_around(lines, idx))
        return

    original_anchor = lines[idx]
    if mode == "after":
        lines[idx] = f"{original_anchor}{hook_code}\n"
    elif mode == "before":
        lines[idx] = f"{hook_code}\n{original_anchor}"
    else:
        fail(f"[{name}] Unknown mode: {mode}")

    if dry_run:
        ok(f"[{name}] Dry-run patch preview for {path}")
        print(preview_around(lines, idx + (1 if mode == 'after' else 0), radius=6))
        return

    write_lines(path, lines)
    verify_lines = read_lines(path)
    verify_idx = find_anchor(verify_lines, func_sig, anchor_line)
    if verify_idx is None:
        fail(f"[{name}] Verification failed: anchor missing after write in {path}")
    if not find_hook_near(verify_lines, verify_idx, hook_code):
        fail(f"[{name}] Verification failed: hook not found near anchor in {path}")

    ok(f"[{name}] Patched and verified in {path}")
    print(preview_around(verify_lines, verify_idx, radius=6))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Preview patches without writing files")
    args = parser.parse_args()

    info("Starting KernelSU hook injection")
    for patch in PATCHES:
        apply_patch(patch, dry_run=args.check)
    ok("All patch operations completed")


if __name__ == "__main__":
    main()
