#!/usr/bin/env python3
# 通过 USB SSH 隧道(127.0.0.1:22, root/alpine)在越狱设备上跑命令。
# 用法: python dev_ssh.py "命令1" ["命令2" ...]
import sys, paramiko

HOST, PORT, USER, PWD = "192.168.9.100", 22, "mobile", "166431"

def run(cmds):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(HOST, port=PORT, username=USER, password=PWD,
                timeout=12, banner_timeout=12, auth_timeout=12,
                look_for_keys=False, allow_agent=False)
    for c in cmds:
        print(f"\n$ {c}")
        stdin, stdout, stderr = cli.exec_command(c, timeout=40)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        if out: print(out.rstrip())
        if err.strip(): print("[stderr]", err.rstrip())
    cli.close()

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        args = ["uname -a", "id"]
    run(args)
