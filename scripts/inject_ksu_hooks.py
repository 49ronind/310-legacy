import os
import sys


def inject_scoped(filepath, func_sig, anchor_line, hook_code, mode="after"):
    if not os.path.exists(filepath):
        print(f"[-] Error: File {filepath} not found!")
        sys.exit(1)

    with open(filepath, "r") as f:
        lines = f.readlines()

    found_func = False
    patched = False

    for i, line in enumerate(lines):
        if func_sig in line:
            found_func = True
        if found_func and anchor_line in line:
            if "CONFIG_KSU" in "".join(lines[max(0, i - 5):i + 5]):
                print(f"[!] Notice: Hooks already verified inside scope of {filepath}")
                return
            if mode == "after":
                lines[i] = line + "
" + hook_code + "
"
            else:
                lines[i] = hook_code + "
" + line
            patched = True
            break

    if not found_func or not patched:
        print(f"[-] Error: Target signature loop matching failed in {filepath}!")
        sys.exit(1)

    with open(filepath, "w") as f:
        f.writelines(lines)

    print(f"[+] Successfully verified and injected scope: {filepath}")


exec_hook = """#ifdef CONFIG_KSU
\textern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);
\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
#endif"""
inject_scoped("fs/exec.c", "do_execveat_common(", "int retval;", exec_hook)

open_hook = """#ifdef CONFIG_KSU
\textern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *flags);
\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif"""
inject_scoped("fs/open.c", "faccessat(", "unsigned int lookup_flags", open_hook)

rw_hook = """#ifdef CONFIG_KSU
\tksu_handle_vfs_read(&file, &buf, &count, &pos);
#endif"""
inject_scoped("fs/read_write.c", "vfs_read(", "if (!(file->f_mode & FMODE_CAN_READ))", rw_hook, mode="before")

stat_hook = """#ifdef CONFIG_KSU
\textern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
\tksu_handle_stat(&dfd, &filename, &flags);
#endif"""
inject_scoped("fs/stat.c", "vfs_statx(", "struct path path;", stat_hook)

reboot_decl = """#ifdef CONFIG_KSU
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif"""
inject_scoped("kernel/reboot.c", "SYSCALL_DEFINE4(reboot", "SYSCALL_DEFINE4(reboot", reboot_decl, mode="before")

reboot_call = """#ifdef CONFIG_KSU
\t{
\t\tint ksu_ret = ksu_handle_sys_reboot(magic1, magic2, cmd, (void __user **)&arg);
\t\tif (ksu_ret) return ksu_ret;
\t}
#endif"""
inject_scoped("kernel/reboot.c", "SYSCALL_DEFINE4(reboot", "int ret = 0;", reboot_call)

input_hook = """#ifdef CONFIG_KSU
\textern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);
\tksu_handle_input_handle_event(&type, &code, &value);
#endif"""
inject_scoped("drivers/input/input.c", "input_handle_event(", "input_get_disposition", input_hook)
