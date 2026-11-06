# -*- coding: utf-8 -*-
"""
驱动 frida-qq-nt-export.js: 让手机 QQ 把自己的加密库导成明文副本。

前置:
  1. 手机已 root, frida-server 已以 root 运行并监听 27042
     adb shell su -c "/data/local/tmp/frida-server -l 0.0.0.0:27042"
  2. adb forward tcp:27042 tcp:27042

用法:
    python run_frida_export.py                      # 重启 QQ 后 attach, 等 120 秒
    python run_frida_export.py --no-restart         # attach 已经在跑的 QQ
    python run_frida_export.py --wait 240 --out-dir /sdcard/Download/qqplain

成功标志: 日志出现 [成功] 行; 随后
    adb pull <out-dir> ./qqplain
"""
import argparse
import os
import subprocess
import sys
import time

import frida

APP_PKG = "com.tencent.mobileqq"
SPLASH = "com.tencent.mobileqq/.activity.SplashActivity"
DEV_ADDR = "127.0.0.1:27042"
OUT_DIR = "/sdcard/Android/data/com.tencent.mobileqq/files/qqplain"
HERE = os.path.dirname(os.path.abspath(__file__))
JS_FILE = os.path.join(HERE, "frida-qq-nt-export.js")
LOG_FILE = os.path.join(HERE, "frida_run.log")

# 这两个库在启动阶段就能拿到; 群资料库需要手动点「联系人 → 群聊」
CORE = ("nt_msg.db", "profile_info.db")


class Tee:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8", buffering=1)

    def __call__(self, *parts):
        line = " ".join(str(p) for p in parts)
        print(line, flush=True)
        self.f.write(line + "\n")


def adb(*args):
    try:
        return subprocess.run(["adb", *args], capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wait", type=int, default=120, help="启动后最多等待多少秒")
    ap.add_argument("--addr", default=DEV_ADDR, help="frida-server 地址")
    ap.add_argument("--pkg", default=APP_PKG, help="目标包名")
    ap.add_argument("--splash", default=SPLASH, help="启动用的 Activity")
    ap.add_argument("--out-dir", default=OUT_DIR, help="手机端输出目录")
    ap.add_argument("--no-restart", action="store_true", help="不重启 QQ, 直接 attach 已在跑的进程")
    args = ap.parse_args()

    log = Tee(LOG_FILE)
    log("=== qq-nt-mobile-exporter · frida 驱动 ===")

    try:
        dev = frida.get_device_manager().add_remote_device(args.addr)
        log("设备连接成功, 可见进程 %d 个" % len(dev.enumerate_processes()))
    except Exception as e:
        log("连接 frida-server 失败: %r" % (e,))
        log("检查: adb forward tcp:27042 tcp:27042; "
            "adb shell su -c '/data/local/tmp/frida-server -l 0.0.0.0:27042'")
        return 1

    with open(JS_FILE, encoding="utf-8") as f:
        js = f.read()

    if not args.no_restart:
        log("强制停止 QQ ...")
        adb("shell", "am", "force-stop", args.pkg)
        time.sleep(2)
        log("正常启动 QQ ... (不要用 spawn, 会超时/停后台)")
        adb("shell", "am", "start", "-n", args.splash)

    pid = 0
    for _ in range(40):
        out = adb("shell", "pidof", args.pkg)
        if out:
            pid = int(out.split()[0])
            break
        time.sleep(1)
    if not pid:
        log("QQ 没起来, 放弃 (手动点开 QQ 后再用 --no-restart)")
        return 1
    log("QQ pid=%d" % pid)
    if not args.no_restart:
        log("给它几秒把库打开 ...")
        time.sleep(8)

    session = dev.attach(pid)

    def on_message(msg, data):
        t = msg.get("type")
        if t == "send":
            p = msg.get("payload") or {}
            log("[手机]", p.get("text", p))
        elif t == "error":
            log("[脚本错误]", msg.get("stack") or msg.get("description"))

    session.on("detached", lambda reason, *a: log("[会话断开]", reason))
    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    log("脚本已注入。若 nt_msg.db 一直不出现，请在手机上点开任意会话。")

    t0 = time.time()
    while time.time() - t0 < args.wait:
        time.sleep(5)
        with open(LOG_FILE, encoding="utf-8") as f:
            text = f.read()
        done = [n for n in CORE if ("[成功] " + n) in text]
        if len(done) == len(CORE) and time.time() - t0 > 30:
            log("核心库已导出 (%s), 结束等待" % "/".join(done))
            break
        log("...已导出 %d 个库 (核心 %d/%d)" % (text.count("[成功]"), len(done), len(CORE)))
    log("等待结束")
    log("--- 手机端产物 ---")
    log(adb("shell", "ls", "-l", args.out_dir) or "(空)")
    log("拉回电脑: adb pull %s ./qqplain" % args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
