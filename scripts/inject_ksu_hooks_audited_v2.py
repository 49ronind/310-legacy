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
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);",
            "#endif",
        ],
    },
    {
        "name": "open",
        "filepath": "fs/open.c",
        "func_sig": "faccessat(",
        "anchor_line": "unsigned int lookup_flags = LOOKUP_FOLLOW;",
        "mode": "after",
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "ksu_handle_faccessat(&dfd, &filename, &mode, NULL);",
            "#endif",
        ],
    },
    {
        "name": "read",
        "filepath": "fs/read_write.c",
        "func_sig": "vfs_read(",
        "anchor_line": "if (!(file->f_mode & FMODE_READ))",
        "mode": "before",
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "ksu_handle_vfs_read(&file, &buf, &count, &pos);",
            "#endif",
        ],
    },
    {
        "name": "stat",
        "filepath": "fs/stat.c",
        "func_sig": "vfs_statx(",
        "anchor_line": "unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;",
        "mode": "after",
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "ksu_handle_stat(&dfd, &filename, &flags);",
            "#endif",
        ],
    },
    {
        "name": "reboot_call",
        "filepath": "kernel/reboot.c",
        "func_sig": "SYSCALL_DEFINE4(reboot",
        "anchor_line": "int ret = 0;",
        "mode": "after",
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "ret = ksu_handle_sys_reboot(magic1, magic2, cmd, (void __user **)&arg);",
            "if (ret)",
            "    return ret;",
            "#endif",
        ],
    },
    {
        "name": "input",
        "filepath": "drivers/input/input.c",
        "func_sig": "input_handle_event(",
        "anchor_line": "int disposition = input_get_disposition(dev, type, code, value);",
        "mode": "after",
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "ksu_handle_input_handle_event(&type, &code, &value);",
            "#endif",
        ],
    },
]

DECLARATIONS = [
    {
        "name": "exec_decl",
        "filepath": "fs/exec.c",
        "anchor_line": "#include <linux/syscalls.h>",
        "mode": "after",
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);",
            "#endif",
        ],
    },
    {
        "name": "open_decl",
        "filepath": "fs/open.c",
        "anchor_line": "#include <linux/syscalls.h>",
        "mode": "after",
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *flags);",
            "#endif",
        ],
    },
    {
        "name": "stat_decl",
        "filepath": "fs/stat.c",
        "anchor_line": "#include <linux/syscalls.h>",
        "mode": "after",
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);",
            "#endif",
        ],
    },
    {
        "name": "reboot_decl",
        "filepath": "kernel/reboot.c",
        "anchor_line": "#include <linux/syscalls.h>",
        "mode": "after",
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);",
            "#endif",
        ],
    },
    {
        "name": "input_decl",
        "filepath": "drivers/input/input.c",
        "anchor_line": "#include <linux/input/mt.h>",
        "mode": "after",
        "hook_code": [
            "#ifdef CONFIG_KSU",
            "extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);",
            "#endif",
        ],
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


def normalize_block(block_lines):
    return [line if line.endswith("\n") else line + "\n" for line in block_lines]


def block_exists(lines, block_lines):
    target = "".join(normalize_block(block_lines))
    return target in "".join(lines)


def preview_around(lines, idx, radius=4):
    start = max(0, idx - radius)
    end = min(len(lines), idx + radius + 1)
    return "\n".join(f"{n+1}: {lines[n].rstrip()}" for n in range(start, end))


def insert_block(lines, idx, block_lines, mode):
    block = normalize_block(block_lines)
    if mode == "after":
        return lines[:idx+1] + block + lines[idx+1:]
    if mode == "before":
        return lines[:idx] + block + lines[idx:]
    fail(f"Unknown mode: {mode}")


def find_anchor_scoped(lines, func_sig, anchor_line):
    in_func = False
    brace_depth = 0
    started_body = False
    for i, line in enumerate(lines):
        if not in_func and func_sig in line:
            in_func = True
        if in_func:
            brace_depth += line.count("{")
            if line.count("{"):
                started_body = True
            if anchor_line in line:
                return i
            brace_depth -= line.count("}")
            if started_body and brace_depth <= 0:
                break
    return None


def apply_decl(patch, dry_run=False):
    lines = read_lines(patch["filepath"])
    if block_exists(lines, patch["hook_code"]):
        ok(f"[{patch['name']}] Declaration already present")
        return
    idx = next((i for i, line in enumerate(lines) if patch["anchor_line"] in line), None)
    if idx is None:
        fail(f"[{patch['name']}] Include anchor not found: {patch['anchor_line']}")
    new_lines = insert_block(lines, idx, patch["hook_code"], patch["mode"])
    if dry_run:
        ok(f"[{patch['name']}] Dry-run declaration preview")
        print(preview_around(new_lines, idx + 1, 5))
        return
    write_lines(patch["filepath"], new_lines)
    verify = read_lines(patch["filepath"])
    if not block_exists(verify, patch["hook_code"]):
        fail(f"[{patch['name']}] Declaration verification failed")
    ok(f"[{patch['name']}] Declaration inserted and verified")


def apply_func_patch(patch, dry_run=False):
    lines = read_lines(patch["filepath"])
    if block_exists(lines, patch["hook_code"]):
        ok(f"[{patch['name']}] Hook already present")
        return
    idx = find_anchor_scoped(lines, patch["func_sig"], patch["anchor_line"])
    if idx is None:
        fail(f"[{patch['name']}] Scoped anchor not found: {patch['anchor_line']}")
    new_lines = insert_block(lines, idx, patch["hook_code"], patch["mode"])
    if dry_run:
        ok(f"[{patch['name']}] Dry-run function patch preview")
        print(preview_around(new_lines, idx + (1 if patch['mode'] == 'after' else 0), 6))
        return
    write_lines(patch["filepath"], new_lines)
    verify = read_lines(patch["filepath"])
    verify_idx = find_anchor_scoped(verify, patch["func_sig"], patch["anchor_line"])
    if verify_idx is None or not block_exists(verify, patch["hook_code"]):
        fail(f"[{patch['name']}] Hook verification failed")
    ok(f"[{patch['name']}] Hook inserted and verified")
    print(preview_around(verify, verify_idx, 6))


def audit_patch_definitions():
    bad = []
    for p in PATCHES:
        joined = "\n".join(p["hook_code"])
        if any(line.strip().startswith("extern int") for line in p["hook_code"]):
            bad.append(f"{p['name']}: declaration inside function patch")
        if '\\t' in joined:
            bad.append(f"{p['name']}: contains literal \\t")
    for p in DECLARATIONS:
        joined = "\n".join(p["hook_code"])
        if '\\t' in joined:
            bad.append(f"{p['name']}: contains literal \\t")
    if bad:
        fail("Audit failed: " + "; ".join(bad))
    ok("Static audit passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Preview patches without writing files")
    args = parser.parse_args()

    audit_patch_definitions()
    info("Applying declaration patches")
    for patch in DECLARATIONS:
        apply_decl(patch, dry_run=args.check)
    info("Applying function hook patches")
    for patch in PATCHES:
        apply_func_patch(patch, dry_run=args.check)
    ok("All patch operations completed")


if __name__ == "__main__":
    main()
