#!/usr/bin/env python3
# 持久 SSH 会话，保持设备上的 frida-server 前台运行（会话不断则进程不死）。
# 后台跑这个脚本，别关。
import paramiko, time, sys

def log(m):
    sys.stdout.write(m + "\n"); sys.stdout.flush()

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.9.100", 22, username="mobile", password="166431",
          timeout=10, look_for_keys=False, allow_agent=False)
ch = c.get_transport().open_session()
ch.get_pty()
ch.exec_command("echo 166431 | sudo -S /var/jb/usr/sbin/frida-server -l 0.0.0.0:27042")
time.sleep(4)
if ch.recv_ready():
    data = ch.recv(500)
    log("startup: " + data.decode("latin1", "replace"))
log("frida-server launched, holding session")
try:
    while True:
        time.sleep(30)
        if ch.exit_status_ready():
            log("frida-server exited code=%d" % ch.recv_exit_status())
            break
except KeyboardInterrupt:
    pass
