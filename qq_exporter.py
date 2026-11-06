# -*- coding: utf-8 -*-
"""
QQ 聊天记录导出器 — 本地小工具
================================
用法:  python qq_exporter.py [--port 8765] [--no-browser]
依赖:  Python 3.8+ 与 cryptography 库 (pip install cryptography)

原理: QQNT(新版QQ) 把聊天记录存在 SQLCipher 加密的本地数据库里,
     密钥只存在于正在运行的 QQ 进程内存中。本工具通过只读方式
     (OpenProcess+ReadProcessMemory, 不注入/不修改QQ) 从内存提取
     密钥, 在缓存目录里解密出明文副本后读取, 原数据库不受影响。

仅处理本人拥有授权的数据。所有数据只在本机处理, 不联网。
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import datetime
import html as html_mod
import json
import os
import re
import sqlite3
import struct
import sys
import threading
import time
import webbrowser
from collections import Counter
from ctypes import windll, byref, sizeof, create_string_buffer
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

try:  # 只在解密加密库时用到; 直接读明文副本(手机导出)时不需要
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    Cipher = algorithms = modes = None


def _app_dir():
    """exe 打包后 __file__ 在临时解压目录, 用 exe 所在目录; 源码运行用脚本目录"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _ui_file():
    # PyInstaller onefile 把数据文件解到 _MEIPASS
    if getattr(sys, "frozen", False):
        p = os.path.join(sys._MEIPASS, "ui.html")
        if os.path.exists(p):
            return p
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui.html")


def _desktop_dir():
    """真实桌面目录(兼容 OneDrive 重定向), 失败则退回工具目录"""
    try:
        import ctypes.wintypes as _wt
        buf = ctypes.create_unicode_buffer(_wt.MAX_PATH)
        windll.shell32.SHGetFolderPathW(None, 0x0000, None, 0, buf)  # CSIDL_DESKTOP
        if buf.value and os.path.isdir(buf.value):
            return os.path.join(buf.value, "QQ聊天记录导出")
    except Exception:
        pass
    return None


APP_DIR = _app_dir()
CACHE_DIR = os.path.join(APP_DIR, "cache")
UI_FILE = _ui_file()
EXPORT_DEFAULT = _desktop_dir() or os.path.join(APP_DIR, "导出记录")

# ── 附加模式: 直接指定一个 nt_db 目录 (例如手机端导出的库) ──────────
# 设置后不再自动定位电脑端 Tencent Files 目录, 直接读取该目录下的 nt_msg.db 等
LOCAL_DB_DIR = None
LOCAL_KEY = None
LOCAL_UIN = "10000"

# ── QQNT 数据库格式常量 ─────────────────────────────────────────
EXT_HEADER = 1024
PAGE_SIZE = 4096
RESERVE = 48
DATA_END = PAGE_SIZE - RESERVE
SALT_SIZE = 16
IV_SIZE = 16
MAGIC = b"SQLite format 3\x00"


class ToolError(Exception):
    """带用户可读提示的错误"""


# ════════════════════════════════════════════════════════════════
#  Windows API: 进程内存只读扫描 (提取数据库密钥)
# ════════════════════════════════════════════════════════════════
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * 260),
    ]


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
READABLE_PROTS = {0x02, 0x04, 0x06, 0x08, 0x20, 0x40, 0x60, 0x80}
MAX_REGION = 256 * 1024 * 1024
HEX_CHARS = set(b"0123456789abcdefABCDEF")


def find_qq_pids():
    snap = windll.kernel32.CreateToolhelp32Snapshot(0x2, 0)
    if snap in (ctypes.c_void_p(-1).value, -1):
        return []
    pe = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)
    pids = []
    if windll.kernel32.Process32First(snap, byref(pe)):
        while True:
            if pe.szExeFile.decode("utf-8", "replace").lower() == "qq.exe":
                pids.append(pe.th32ProcessID)
            if not windll.kernel32.Process32Next(snap, byref(pe)):
                break
    windll.kernel32.CloseHandle(snap)
    return pids


def _read_mem(handle, addr, size):
    buf = create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if windll.kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, byref(n)):
        return buf.raw[: n.value]
    return None


def scan_keys_for_salts(salt_hexes):
    """在所有 QQ.exe 进程内存里找 x'<64hex密钥><32hex盐>' → {盐: 密钥hex}"""
    salt_hexes = [s for s in salt_hexes]
    if not salt_hexes:
        return {}
    pids = find_qq_pids()
    if not pids:
        raise ToolError("没有找到正在运行的 QQ。提取密钥需要 QQ 正在运行并已登录, "
                        "请先打开 QQ 登录该账号, 再重试。")
    needles = {sh: sh.encode("ascii") for sh in salt_hexes}
    results = {}
    for pid in pids:
        if len(results) == len(salt_hexes):
            break
        handle = windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            continue
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        try:
            while len(results) < len(salt_hexes):
                if windll.kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr), byref(mbi), sizeof(mbi)) == 0:
                    break
                base = mbi.BaseAddress or 0
                size = mbi.RegionSize
                if (mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in READABLE_PROTS
                        and 0 < size <= MAX_REGION):
                    data = _read_mem(handle, base, size)
                    if data:
                        for sh, needle in needles.items():
                            if sh in results:
                                continue
                            idx = data.find(needle)
                            if (idx >= 66 and idx + 33 <= len(data)
                                    and data[idx - 66: idx - 64] == b"x'"
                                    and data[idx + 32: idx + 33] == b"'"
                                    and all(c in HEX_CHARS for c in data[idx - 64: idx])):
                                results[sh] = data[idx - 64: idx].decode("ascii").lower()
                nxt = base + size
                if nxt <= addr or nxt >= 0x7FFFFFFFFFFF:
                    break
                addr = nxt
        finally:
            windll.kernel32.CloseHandle(handle)
    return results


# ════════════════════════════════════════════════════════════════
#  数据库解密 (文件 → 明文缓存副本)
# ════════════════════════════════════════════════════════════════
def db_salt(src):
    with open(src, "rb") as f:
        f.seek(EXT_HEADER)
        s = f.read(SALT_SIZE)
    if len(s) < SALT_SIZE:
        raise ToolError(f"文件读取失败或过小: {src}")
    return s.hex()


def decrypt_file(src, dst, key_hex, progress=None):
    """流式解密: 跳过1024字节自定义头, AES-256-CBC 逐页解密"""
    if Cipher is None:
        raise ToolError("解密加密数据库需要 cryptography 库: pip install cryptography")
    size = os.path.getsize(src)
    body_len = size - EXT_HEADER
    if body_len < PAGE_SIZE:
        raise ToolError(f"数据库文件异常: {src}")
    n_pages = body_len // PAGE_SIZE
    key = bytes.fromhex(key_hex)
    aes = algorithms.AES(key)
    with open(src, "rb") as fi, open(dst + ".part", "wb") as fo:
        fi.seek(EXT_HEADER)
        for p in range(n_pages):
            page = fi.read(PAGE_SIZE)
            if len(page) < PAGE_SIZE:
                break
            d = Cipher(aes, modes.CBC(page[DATA_END: DATA_END + IV_SIZE])).decryptor()
            if p == 0:
                pt = MAGIC + d.update(page[SALT_SIZE:DATA_END])
                b = bytearray(pt)
                b[20] = 0
                fo.write(b)
                fo.write(b"\x00" * RESERVE)
            else:
                fo.write(d.update(page[:DATA_END]))
                fo.write(b"\x00" * RESERVE)
            if progress and p % 8192 == 0:
                progress(p / n_pages)
    os.replace(dst + ".part", dst)
    return n_pages


def nt_db_path(root, uin, name):
    if LOCAL_DB_DIR:
        p = os.path.join(LOCAL_DB_DIR, name)
    else:
        p = os.path.join(root, uin, "nt_qq", "nt_db", name)
    if not os.path.exists(p):
        raise ToolError(f"找不到数据库: {p}")
    return p


def _is_plain_db(p):
    """库文件开头就是 SQLite magic → 已是明文副本, 不需要密钥解密"""
    try:
        with open(p, "rb") as f:
            return f.read(16) == MAGIC
    except OSError:
        return False


def ensure_plain(root, uin, name, keyring, refresh=False, progress=None):
    """返回解密后的明文库路径 (有缓存且未要求刷新时直接复用)"""
    src = nt_db_path(root, uin, name)
    if _is_plain_db(src):
        # 手机端用 sqlcipher_export 导出的明文副本, 直接读, 无需密钥
        return src, False
    if LOCAL_KEY:
        keyring[db_salt(src)] = LOCAL_KEY
    os.makedirs(CACHE_DIR, exist_ok=True)
    st = os.stat(src)
    dst = os.path.join(CACHE_DIR, f"{uin}.{name}.{st.st_size}.{int(st.st_mtime)}.plain.db")
    if os.path.exists(dst) and not refresh:
        return dst, False
    salt = db_salt(src)
    if salt not in keyring:
        found = scan_keys_for_salts([salt])
        if salt not in found:
            raise ToolError(
                f"无法从 QQ 进程内存中找到 {name} 的密钥。\n"
                f"通常原因: QQ 未运行, 或 QQ 当前登录的不是账号 {uin}。\n"
                f"请在 QQ 中登录该账号后重试 (已解密的缓存仍可使用)。")
        keyring.update(found)
    decrypt_file(src, dst, keyring[salt], progress)
    return dst, True


# ════════════════════════════════════════════════════════════════
#  容错读取工具 (QQNT 库自带损坏页, 逐行跳过)
# ════════════════════════════════════════════════════════════════
def try_query(con, sql, params=()):
    try:
        return con.execute(sql, params).fetchall()
    except sqlite3.Error:
        return None


def walk_table(con, table, cols, where="", params=()):
    """优先直接查询; 遇到损坏页时退化为 rowid 清单+逐行读取, 跳过坏行"""
    q = f'SELECT rowid,{cols} FROM "{table}" {where}'
    rows = try_query(con, q, params)
    if rows is not None:
        return rows
    out = []
    rids = try_query(con, f'SELECT rowid FROM "{table}"')
    if rids is None:
        return out
    for (rid,) in rids:
        r = try_query(con, f'SELECT rowid,{cols} FROM "{table}" WHERE rowid=?', (rid,))
        if r:
            out.append(r[0])
    return out


def read_fts_texts(plain_fts, table, peer):
    """FTS 文本表: {消息ID: 文本} (容错)"""
    con = sqlite3.connect(plain_fts)
    try:
        rows = try_query(con, f'SELECT "40001","41701" FROM "{table}" WHERE "40021"=?', (peer,))
        if rows is None:
            rows = []
            for r in walk_table(con, table, '"40001","41701","40021"'):
                if len(r) >= 4 and r[3] == peer and r[2]:
                    rows.append((r[1], r[2]))
        return {mid: txt for mid, txt in rows if txt}
    finally:
        con.close()


# ════════════════════════════════════════════════════════════════
#  Protobuf 解析与消息渲染
# ════════════════════════════════════════════════════════════════
def _rv(buf, i):
    v = 0
    sh = 0
    while True:
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << sh
        sh += 7
        if not b & 0x80:
            return v, i


def parse_pb(buf, depth=0, maxdepth=5):
    out = []
    i = 0
    while i < len(buf):
        try:
            tag, i = _rv(buf, i)
            fn, wt_ = tag >> 3, tag & 7
            if fn == 0:
                break
            if wt_ == 0:
                v, i = _rv(buf, i)
                out.append((fn, v))
            elif wt_ == 2:
                ln, i = _rv(buf, i)
                data = buf[i:i + ln]
                i += ln
                if depth < maxdepth and ln > 0:
                    try:
                        out.append((fn, parse_pb(data, depth + 1, maxdepth)))
                    except Exception:
                        out.append((fn, data))
                else:
                    out.append((fn, data))
            elif wt_ == 5:
                out.append((fn, int.from_bytes(buf[i:i + 4], "little")))
                i += 4
            elif wt_ == 1:
                out.append((fn, int.from_bytes(buf[i:i + 8], "little")))
                i += 8
            else:
                break
        except Exception:
            break
    return out


def find_strings(node, acc):
    if isinstance(node, list):
        for _f, v in node:
            find_strings(v, acc)
    elif isinstance(node, bytes):
        try:
            s = node.decode("utf-8")
            if s:
                acc.append(s)
        except Exception:
            pass


def seg_render(seg):
    """把一个 MsgContent 段渲染成可读标记; 文本段返回 None(文本在FTS)"""
    ctype = next((v for f, v in seg if f == 45002), None)
    body = [(f, v) for f, v in seg if f not in (45001, 45002)]
    if ctype == 1:
        return None
    if ctype == 2:
        acc = []
        find_strings(body, acc)
        for s in acc:
            if s.startswith("[") and s.endswith("]") and len(s) < 20:
                return s
        return "[视频]" if any(f in (45503, 45504) for f, _v in body) else "[图片]"
    if ctype == 3:
        acc = []
        find_strings(body, acc)
        fn = next((s for s in acc if "." in s and len(s) < 80), "")
        return f"[文件 {fn}]" if fn else "[文件]"
    if ctype == 4:
        return "[视频]"
    if ctype == 6:
        acc = []
        find_strings(body, acc)
        name = next((s for s in acc if s and not s.startswith("/") and len(s) < 30), "")
        return f"[表情 {name}]" if name else "[表情]"
    if ctype == 7:
        inner = []
        for f, v in body:
            if f == 47423 and isinstance(v, list):
                sub = next((vv for ff, vv in v if ff == 45101), None)
                if isinstance(sub, list):
                    acc = []
                    find_strings(sub, acc)
                    inner += acc
        quoted = "".join(inner)[:60]
        return f"[回复: {quoted}]" if quoted else "[回复消息]"
    if ctype == 8:
        return "[语音]"
    acc = []
    find_strings(body, acc)
    if acc:
        return "[" + " ".join(s for s in acc if len(s) < 50)[:80] + "]"
    return f"[消息类型{ctype}]"


def seg_inline_text(seg):
    """type=1 段里内嵌的文本(群消息有时有); 没有则 None"""
    sub = next((v for f, v in seg if f == 45101), None)
    if isinstance(sub, list):
        acc = []
        find_strings(sub, acc)
        if acc:
            return "".join(acc)
    return None


def _read_varint(buf, i):
    v = 0
    shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << shift
        if not (b & 0x80):
            return v, i
        shift += 7
        if shift > 63:
            break
    return None, i


def _walk(buf):
    """极简 protobuf 遍历: yield (字段号, wiretype, 值)"""
    i = 0
    n = len(buf)
    while i < n:
        tag, i = _read_varint(buf, i)
        if tag is None:
            return
        f, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = _read_varint(buf, i)
            if v is None:
                return
            yield f, wt, v
        elif wt == 1:
            yield f, wt, buf[i:i + 8]
            i += 8
        elif wt == 2:
            ln, i = _read_varint(buf, i)
            if ln is None:
                return
            yield f, wt, buf[i:i + ln]
            i += ln
        elif wt == 5:
            yield f, wt, buf[i:i + 4]
            i += 4
        else:
            return


def _clean_utf8(raw):
    """手机版 45101 直接放 UTF-8 原文; 电脑版这里是一段嵌套结构, 会带着控制字符被拒掉"""
    if not raw:
        return None
    try:
        t = raw.decode("utf-8")
    except Exception:
        return None
    if not t.strip():
        return None
    bad = sum(1 for ch in t if ord(ch) < 32 and ch not in "\n\r\t")
    if bad or bad * 20 > len(t):
        return None
    return t


def mobile_text(blob):
    """手机版 NTQQ: 40800 段里 45002==1 的 45101 是原始文本字节。多个文本段拼接"""
    parts = []
    for f, wt, seg in _walk(blob):
        if f != 40800 or wt != 2 or not isinstance(seg, bytes):
            continue
        ctype = None
        texts = []
        for f2, wt2, v2 in _walk(seg):
            if f2 == 45002 and wt2 == 0:
                ctype = v2
            elif f2 == 45101 and wt2 == 2 and isinstance(v2, bytes):
                texts.append(v2)
        if ctype == 1:
            for raw in texts:
                t = _clean_utf8(raw)
                if t:
                    parts.append(t)
    return "".join(parts) if parts else None


def render_40800(blob):
    """返回 (文本或None, 标记列表)"""
    if not blob:
        return None, []
    marks = []
    inline = None
    for fn, v in parse_pb(blob):
        if fn == 40800 and isinstance(v, list):
            m = seg_render(v)
            if m:
                marks.append(m)
            elif inline is None:
                inline = seg_inline_text(v)
    mt = mobile_text(blob)
    return (inline or mt), marks


# ════════════════════════════════════════════════════════════════
#  业务: 扫描账号 / 会话列表 / 导出
# ════════════════════════════════════════════════════════════════
def normalize_root(path):
    path = (path or "").strip().strip('"')
    if LOCAL_DB_DIR:
        return path if (path and os.path.isdir(path)) else LOCAL_DB_DIR
    if not path:
        raise ToolError("请填写 Tencent Files 目录路径")
    if not os.path.isdir(path):
        raise ToolError(f"目录不存在: {path}")
    inner = os.path.join(path, "Tencent Files")
    if os.path.isdir(inner):
        return inner
    return path


def scan_accounts(root):
    if LOCAL_DB_DIR:
        nt = os.path.join(LOCAL_DB_DIR, "nt_msg.db")
        if not os.path.exists(nt):
            raise ToolError(f"--nt-dir 下没有 nt_msg.db: {LOCAL_DB_DIR}")
        total = sum(
            os.path.getsize(os.path.join(LOCAL_DB_DIR, fn))
            for fn in os.listdir(LOCAL_DB_DIR)
            if fn.endswith(".db"))
        return [{
            "uin": LOCAL_UIN,
            "dir": LOCAL_DB_DIR,
            "dbsize": total,
            "mtime": int(os.path.getmtime(nt)),
        }]
    root = normalize_root(root)
    accounts = []
    for name in os.listdir(root):
        if not name.isdigit():
            continue
        dbdir = os.path.join(root, name, "nt_qq", "nt_db")
        if not os.path.isdir(dbdir):
            continue
        nt = os.path.join(dbdir, "nt_msg.db")
        if not os.path.exists(nt):
            continue
        try:
            with open(nt, "rb") as f:
                head = f.read(48)
            if head[:15] != b"SQLite header 3":
                continue  # 非新版NT格式
        except OSError:
            continue
        total = sum(
            os.path.getsize(os.path.join(dbdir, fn))
            for fn in os.listdir(dbdir)
            if fn.endswith(".db"))
        accounts.append({
            "uin": name,
            "dir": os.path.join(root, name),
            "dbsize": total,
            "mtime": int(os.path.getmtime(nt)),
        })
    if not accounts:
        raise ToolError(f"在 {root} 下没有找到新版QQ(NT)的账号数据目录。\n"
                        f"请确认路径指向包含 QQ 号文件夹的 Tencent Files 目录。")
    accounts.sort(key=lambda a: -a["mtime"])
    return accounts


def ts_str(ts, fmt="%Y-%m-%d %H:%M:%S"):
    try:
        return datetime.datetime.fromtimestamp(ts).strftime(fmt)
    except Exception:
        return "?"


def get_my_uid(con):
    """自己的uid: 方向=1(发出)的消息的发送者"""
    r = try_query(con, 'SELECT "40020",COUNT(*) n FROM c2c_msg_table '
                       'WHERE "40013"=1 AND "40020" IS NOT NULL '
                       'GROUP BY "40020" ORDER BY n DESC LIMIT 1')
    if r:
        return r[0][0]
    r = try_query(con, 'SELECT "40020",COUNT(*) n FROM c2c_msg_table '
                       'WHERE "40020" IS NOT NULL GROUP BY "40020" ORDER BY n DESC LIMIT 1')
    return r[0][0] if r else None


def list_conversations(root, uin, keyring, refresh, prog):
    root = normalize_root(root)
    prog("正在检查密钥与缓存", 0.02)
    nt_plain, _ = ensure_plain(root, uin, "nt_msg.db", keyring, refresh,
                               lambda p: prog("正在解密消息库 nt_msg.db", 0.02 + p * 0.7))
    prog("正在统计会话", 0.75)
    con = sqlite3.connect(nt_plain)
    # 好友会话 (时间戳为0的系统消息不计入范围)
    c2c = try_query(con, 'SELECT "40021",COUNT(*),'
                         'MIN(CASE WHEN "40050">0 THEN "40050" END),'
                         'MAX(CASE WHEN "40050">0 THEN "40050" END) '
                         'FROM c2c_msg_table GROUP BY "40021"')
    if c2c is None:
        c = Counter()
        tmin = {}
        tmax = {}
        for r in walk_table(con, "c2c_msg_table", '"40021","40050"'):
            peer = r[1]
            if not peer:
                continue
            c[peer] += 1
            ts = r[2] or 0
            if ts > 0:
                tmin[peer] = min(tmin.get(peer, ts), ts)
                tmax[peer] = max(tmax.get(peer, 0), ts)
        c2c = [(k, c[k], tmin.get(k, 0), tmax.get(k, 0)) for k in c]
    my_uid = get_my_uid(con)
    # 群会话
    grp = try_query(con, 'SELECT "40021",COUNT(*),'
                         'MIN(CASE WHEN "40050">0 THEN "40050" END),'
                         'MAX(CASE WHEN "40050">0 THEN "40050" END) '
                         'FROM group_msg_table GROUP BY "40021"')
    if grp is None:
        c = Counter()
        tmin = {}
        tmax = {}
        for row in walk_table(con, "group_msg_table", '"40021","40050"'):
            peer = row[1]
            if not peer:
                continue
            c[peer] += 1
            ts = row[2] or 0
            if ts > 0:
                tmin[peer] = min(tmin.get(peer, ts), ts)
                tmax[peer] = max(tmax.get(peer, 0), ts)
        grp = [(k, c[k], tmin.get(k, 0), tmax.get(k, 0)) for k in c]

    prog("正在读取好友资料", 0.85)
    nick, uid2uin = {}, {}
    try:
        prof_plain, _ = ensure_plain(root, uin, "profile_info.db", keyring, refresh)
        p = sqlite3.connect(prof_plain)
        for r in walk_table(p, "profile_info_v6", '"1000","20002"'):
            if len(r) >= 3 and r[1] and r[2]:
                nick[r[1]] = r[2]
        for r in walk_table(p, "buddy_list", '"1000","1002"'):
            if len(r) >= 3 and r[1] and r[2]:
                uid2uin[r[1]] = str(r[2])
        p.close()
    except ToolError:
        pass

    prog("正在读取群资料", 0.95)
    gnames = {}
    try:
        gi_plain, _ = ensure_plain(root, uin, "group_info.db", keyring, refresh)
        g = sqlite3.connect(gi_plain)
        for r in try_query(g, 'SELECT "60001","60007" FROM group_detail_info_ver1') or []:
            if r[1]:
                gnames[str(r[0])] = r[1]
        for r in try_query(g, 'SELECT "60001","60007" FROM group_list') or []:
            if r[1]:
                gnames.setdefault(str(r[0]), r[1])
        g.close()
    except ToolError:
        pass
    con.close()

    convs = []
    for peer, n, t0, t1 in c2c:
        if peer == my_uid:
            continue  # 自己其他设备的同步会话一般无意义
        convs.append({
            "kind": "c2c", "key": peer, "uin": uid2uin.get(peer, ""),
            "name": nick.get(peer, ""), "count": n,
            "tmin": t0 or 0, "tmax": t1 or 0,
        })
    for gid, n, t0, t1 in grp:
        convs.append({
            "kind": "group", "key": str(gid), "uin": str(gid),
            "name": gnames.get(str(gid), ""), "count": n,
            "tmin": t0 or 0, "tmax": t1 or 0,
        })
    convs.sort(key=lambda c: -c["count"])
    prog("完成", 1.0)
    return {"my_uid": my_uid, "conversations": convs}


def load_group_members(root, uin, keyring, gid):
    """群成员: {uid: 名称}, {uinStr: 名称}"""
    names = {}
    try:
        gi_plain, _ = ensure_plain(root, uin, "group_info.db", keyring)
        g = sqlite3.connect(gi_plain)
        rows = try_query(g, 'SELECT "1000","1002","64003","20002" FROM group_member3 WHERE "60001"=?', (int(gid),))
        if rows is None:
            rows = [r[1:] for r in walk_table(g, "group_member3", '"60001","1000","1002","64003","20002"')
                    if len(r) >= 5 and str(r[1]) == str(gid)]
        for uid, qu, card, nk in rows or []:
            nm = card or nk
            if not nm:
                continue
            if uid:
                names[uid] = nm
            if qu:
                names[str(qu)] = nm
        g.close()
    except (ToolError, ValueError):
        pass
    return names


def sanitize(name, maxlen=50):
    return re.sub(r'[\\/:*?"<>|\r\n\t]', "_", name).strip()[:maxlen] or "未命名"


def export_items(root, uin, sel, fmt, outdir, keyring, refresh, prog):
    """sel: [{kind,key}]; fmt in txt/html/csv; 返回文件列表"""
    root = normalize_root(root)
    os.makedirs(outdir, exist_ok=True)
    nt_plain, _ = ensure_plain(root, uin, "nt_msg.db", keyring, refresh,
                               lambda p: prog("确保消息库已解密", p * 0.2))
    con = sqlite3.connect(nt_plain)

    need_group = any(s["kind"] == "group" for s in sel)
    need_c2c = any(s["kind"] == "c2c" for s in sel)
    fts_c2c = fts_grp = None
    # 文本索引库是可选的: 手机端导出常常只拿到 nt_msg.db, 正文直接从 40800 解出
    if need_c2c:
        prog("准备好友消息文本索引", 0.22)
        try:
            fts_c2c, _ = ensure_plain(root, uin, "buddy_msg_fts.db", keyring, refresh,
                                      lambda p: prog("解密好友文本索引 buddy_msg_fts.db", 0.2 + p * 0.1))
        except ToolError:
            fts_c2c = None
    if need_group:
        prog("准备群消息文本索引 (首次约需1-2分钟)", 0.35)
        try:
            fts_grp, _ = ensure_plain(root, uin, "group_msg_fts.db", keyring, refresh,
                                      lambda p: prog("解密群文本索引 group_msg_fts.db (首次约1-2分钟)", 0.35 + p * 0.25))
        except ToolError:
            fts_grp = None

    files = []
    total = len(sel)
    for i, s in enumerate(sel):
        base = 0.6 + 0.4 * i / max(total, 1)
        prog(f"导出 {i + 1}/{total}: {s.get('name') or s.get('key')}", base)
        try:
            label = f"导出 {i + 1}/{total}: {s.get('name') or s.get('key')}"
            f = export_one(con, root, uin, s, fmt, outdir, keyring, fts_c2c, fts_grp,
                           lambda st, p, _label=label, _base=base, _tot=total:
                               prog(_label + (f" · {st}" if st else ""),
                                    _base + p * 0.4 / max(_tot, 1)))
            files.append(f)
        except ToolError:
            raise
        except Exception as e:
            files.append({"error": f"{s.get('name') or s.get('key')}: {e}"})
    prog("完成", 1.0)
    return files


def fetch_conversation(con, table, peer, prog):
    """按时间序取会话消息 (安全列), 容错"""
    rows = try_query(con, f'SELECT rowid,"40001","40020","40050" FROM "{table}" '
                          f'WHERE "40021"=? ORDER BY "40050"', (peer,))
    if rows is not None:
        return rows
    rows = []
    for r in walk_table(con, table, '"40001","40020","40021","40050"'):
        if len(r) >= 5 and r[3] == peer:
            rows.append((r[0], r[1], r[2], r[4]))
    rows.sort(key=lambda r: r[3] or 0)
    return rows


def export_one(con, root, uin, s, fmt, outdir, keyring, fts_c2c, fts_grp, prog):
    kind, peer = s["kind"], s["key"]
    table = "c2c_msg_table" if kind == "c2c" else "group_msg_table"
    prog("读取消息列表", 0.05)
    rows = fetch_conversation(con, table, peer, prog)
    if not rows:
        raise ToolError("该会话没有可读取的消息(可能全部位于损坏页)")

    prog("提取消息文本", 0.3)
    texts = {}
    if kind == "c2c" and fts_c2c:
        texts = read_fts_texts(fts_c2c, "buddy_msg_fts", peer)
    elif kind == "group" and fts_grp:
        texts = read_fts_texts(fts_grp, "group_msg_fts", peer)

    members = {}
    my_uid = None
    if kind == "group":
        my_uid = get_my_uid(con)
        members = load_group_members(root, uin, keyring, peer)

    prog("解码消息内容", 0.5)
    msgs = []
    n_fail = 0
    for idx, (rid, mid, sender, ts) in enumerate(rows):
        if idx % 2000 == 0:
            prog("解码消息内容", 0.5 + 0.4 * idx / len(rows))
        blob = None
        sender_qq = ""
        r = try_query(con, f'SELECT "40800","40033" FROM "{table}" WHERE rowid=?', (rid,))
        if r and r[0]:
            blob = r[0][0]
            if len(r[0]) > 1 and r[0][1]:
                sender_qq = str(r[0][1])
        else:
            n_fail += 1
        inline, marks = render_40800(blob)
        text = texts.get(mid) or inline
        if kind == "c2c":
            who = "TA" if sender == peer else "我"
            who_long = who
        else:
            who = "我" if (sender and sender == my_uid) else "成员"
            who_long = members.get(sender or "") or members.get(sender_qq) or sender_qq or who
        msgs.append({"ts": ts or 0, "who": who, "who_long": who_long,
                     "sender_qq": sender_qq, "text": text, "marks": marks})

    title = s.get("name") or (f"QQ {s.get('uin')}" if s.get("uin") else peer)
    sub = f"{s.get('uin','')} · {len(msgs)}条 · {ts_str(msgs[0]['ts'],'%Y-%m-%d')} ~ {ts_str(msgs[-1]['ts'],'%Y-%m-%d')}"
    fname = sanitize(f"{('好友' if kind=='c2c' else '群')}_"
                     f"{s.get('uin') or ''}_{s.get('name') or peer}")
    if fmt == "txt":
        path = os.path.join(outdir, fname + ".txt")
        write_txt(path, uin, title, sub, msgs, n_fail)
    elif fmt == "csv":
        path = os.path.join(outdir, fname + ".csv")
        write_csv(path, uin, title, msgs)
    else:
        path = os.path.join(outdir, fname + ".html")
        write_html(path, uin, title, sub, msgs, n_fail, show_names=(kind == "group"))
    return {"file": os.path.abspath(path), "name": title, "count": len(msgs), "fail": n_fail}


def msg_line(m):
    body = m["text"] or ""
    if m["marks"]:
        body = (body + " " + " ".join(m["marks"])).strip()
    if not body:
        body = "[无文本内容]"
    return body


def write_txt(path, uin, title, sub, msgs, n_fail):
    head = (f"{title}  ({sub})\n账号: {uin}\n"
            f"导出时间: {datetime.datetime.now():%Y-%m-%d %H:%M}\n"
            + (f"注: {n_fail} 条消息因本地数据库损坏页无法读取\n" if n_fail else "")
            + "=" * 60 + "\n\n")
    lines = [f"[{ts_str(m['ts'])}] {m['who']}: {msg_line(m)}" for m in msgs]
    with open(path, "w", encoding="utf-8-sig") as f:
        f.write(head + "\n".join(lines))


def write_csv(path, uin, title, msgs):
    import csv
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["时间", "发送方", "发送者", "内容"])
        for m in msgs:
            w.writerow([ts_str(m["ts"]), m["who"], m["who_long"], msg_line(m)])


def write_html(path, uin, title, sub, msgs, n_fail, show_names=False):
    esc = html_mod.escape
    note = f" · {n_fail}条损坏" if n_fail else ""
    head = (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{esc(title)}</title><style>"
        "body{font-family:'Segoe UI','Microsoft YaHei',system-ui,sans-serif;background:#f2f4f7;margin:0;padding:24px;}"
        ".wrap{max-width:820px;margin:0 auto}"
        "h1{font-size:20px;color:#1c2430;margin:0 0 4px}"
        ".sub{color:#7a8699;font-size:13px;margin-bottom:20px}"
        ".day{text-align:center;color:#98a2b3;font-size:12px;margin:18px 0 10px}"
        ".m{display:flex;margin:7px 0}"
        ".m.me{justify-content:flex-end}"
        ".av{width:34px;height:34px;border-radius:8px;background:#c5d2e3;flex:none;display:flex;align-items:center;justify-content:center;font-size:15px;color:#fff}"
        ".m.me .av{background:#0f7be0}"
        ".body{max-width:70%;margin:0 10px}"
        ".nm{font-size:12px;color:#98a2b3;margin:0 0 3px 4px}"
        ".m.me .nm{text-align:right;margin:0 4px 3px 0}"
        ".bub{display:inline-block;padding:8px 12px;border-radius:10px;background:#fff;box-shadow:0 1px 2px rgba(16,24,40,.06);font-size:14.5px;line-height:1.55;word-break:break-word;white-space:pre-wrap}"
        ".m.me .bub{background:#0f7be0;color:#fff}"
        ".mk{color:#8fa3bf;font-size:13px}"
        ".m.me .mk{color:#cfe4ff}"
        "time{font-size:11px;color:#b6bfcc;margin:2px 4px 0;display:block}"
        ".m.me time{text-align:right}"
        "</style></head><body><div class=\"wrap\">"
        f"<h1>{esc(title)}</h1>"
        f"<div class=\"sub\">{esc(sub)} · 账号 {esc(str(uin))} · 导出于 "
        f"{datetime.datetime.now():%Y-%m-%d %H:%M}{esc(note)}</div>"
    )
    b = [head]
    last_day = ""
    for m in msgs:
        day = ts_str(m["ts"], "%Y-%m-%d")
        if day != last_day:
            b.append(f'<div class="day">{day}</div>')
            last_day = day
        who_esc = html_mod.escape(m["who_long"] or m["who"])
        txt = html_mod.escape(m["text"] or "")
        marks = "".join(f'<span class="mk">{html_mod.escape(x)}</span> ' for x in m["marks"])
        body = (txt + " " + marks).strip() or '<span class="mk">[无文本内容]</span>'
        cls = "me" if m["who"] == "我" else ""
        nm = f'<div class="nm">{who_esc}</div>' if (show_names and m["who"] != "我") else ""
        b.append(f'<div class="m {cls}"><div class="av">{who_esc[:1] or "?"}</div>'
                 f'<div class="body">{nm}<div class="bub">{body}</div>'
                 f'<time>{ts_str(m["ts"])}</time></div></div>')
    b.append("</div></body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(b))


# ════════════════════════════════════════════════════════════════
#  后台任务与 HTTP 服务
# ════════════════════════════════════════════════════════════════
JOBS = {}
JOB_LOCK = threading.Lock()
JOB_SEQ = [0]
KEYRINGS = {}  # root|uin -> {salt: key}


def keyring_for(root, uin):
    k = f"{root}|{uin}"
    if k not in KEYRINGS:
        KEYRINGS[k] = {}
    return KEYRINGS[k]


def new_job(fn):
    with JOB_LOCK:
        JOB_SEQ[0] += 1
        jid = f"job{JOB_SEQ[0]}"
        JOBS[jid] = {"stage": "排队中", "pct": 0, "log": [], "done": False,
                     "error": None, "result": None, "t": time.time()}
    th = threading.Thread(target=_run_job, args=(jid, fn), daemon=True)
    th.start()
    return jid


def _run_job(jid, fn):
    job = JOBS[jid]

    def prog(stage, pct):
        job["stage"] = stage
        job["pct"] = max(0.0, min(1.0, pct))
        job["t"] = time.time()

    try:
        job["result"] = fn(prog)
        job["stage"] = "完成"
        job["pct"] = 1.0
    except ToolError as e:
        job["error"] = str(e)
    except Exception as e:
        job["error"] = f"发生错误: {e!r}"
    finally:
        job["done"] = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            try:
                with open(UI_FILE, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except OSError:
                self._json({"error": "缺少 ui.html"}, 500)
        elif u.path == "/api/ping":
            self._json({"ok": True, "default_root": default_root(),
                        "export_default": EXPORT_DEFAULT})
        elif u.path.startswith("/api/job"):
            jid = (u.query or "").replace("id=", "")
            with JOB_LOCK:
                job = JOBS.get(jid)
            if not job:
                self._json({"error": "任务不存在"}, 404)
            else:
                self._json({k: job[k] for k in ("stage", "pct", "done", "error", "result")})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        body = self._body()
        try:
            if u.path == "/api/scan":
                self._json({"accounts": scan_accounts(body.get("root", ""))})
            elif u.path == "/api/prepare":
                root = normalize_root(body.get("root", ""))
                uin = str(body.get("uin", "")).strip()
                if not uin.isdigit():
                    raise ToolError("账号参数无效")
                refresh = bool(body.get("refresh"))
                ring = keyring_for(root, uin)

                def fn(prog):
                    return list_conversations(root, uin, ring, refresh, prog)
                self._json({"job": new_job(fn)})
            elif u.path == "/api/export":
                root = normalize_root(body.get("root", ""))
                uin = str(body.get("uin", "")).strip()
                sel = body.get("items") or []
                fmt = body.get("format", "txt")
                if fmt not in ("txt", "html", "csv"):
                    raise ToolError("格式仅支持 txt/html/csv")
                outdir = body.get("outdir") or EXPORT_DEFAULT
                refresh = bool(body.get("refresh"))
                ring = keyring_for(root, uin)

                def fn(prog):
                    return export_items(root, uin, sel, fmt, outdir, ring, refresh, prog)
                self._json({"job": new_job(fn)})
            elif u.path == "/api/open":
                p = body.get("path", "")
                if os.path.isdir(p):
                    os.startfile(p)  # noqa
                    self._json({"ok": True})
                else:
                    raise ToolError("目录不存在")
            else:
                self._json({"error": "not found"}, 404)
        except ToolError as e:
            self._json({"error": str(e)}, 400)
        except Exception as e:
            self._json({"error": f"{e!r}"}, 500)


def default_root():
    cands = []
    home = os.path.expanduser("~")
    cands.append(os.path.join(home, "Documents", "Tencent Files"))
    for d in ("E:\\", "D:\\", "C:\\", "F:\\"):
        cands.append(os.path.join(d, "QQInfo", "Tencent Files"))
        cands.append(os.path.join(d, "Tencent Files"))
    for c in cands:
        if os.path.isdir(c):
            return c
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--nt-dir",
                    help="直接指定一个 nt_db 目录(含 nt_msg.db 等), 跳过电脑端自动定位")
    ap.add_argument("--key",
                    help="该目录数据库的 SQLCipher 密钥(64位hex); 明文副本不需要")
    ap.add_argument("--uin", default="10000",
                    help="--nt-dir 模式下的账号标识(仅用于缓存命名)")
    args = ap.parse_args()

    global LOCAL_DB_DIR, LOCAL_KEY, LOCAL_UIN
    if args.nt_dir:
        d = os.path.abspath(args.nt_dir)
        if not os.path.isdir(d):
            print(f"目录不存在: {d}")
            return
        LOCAL_DB_DIR = d
        LOCAL_KEY = (args.key or "").strip() or None
        LOCAL_UIN = str(args.uin).strip() or "10000"
        print(f"[本地库模式] {d}  uin={LOCAL_UIN}  密钥={'已提供' if LOCAL_KEY else '不需要(明文库)'}")

    os.makedirs(CACHE_DIR, exist_ok=True)
    port = args.port
    url = None
    # 单实例: 若默认端口上已是本工具, 直接复用(再开浏览器即可)
    try:
        import urllib.request
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ping", timeout=1)
        if json.loads(r.read()).get("ok"):
            url = f"http://127.0.0.1:{port}/"
            print(f"工具已在运行, 直接打开现有页面: {url}")
    except Exception:
        pass
    httpd = None
    if not url:
        for _ in range(10):
            try:
                httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
                break
            except OSError:
                port += 1
        if not httpd:
            print("无法启动本地服务")
            return
        url = f"http://127.0.0.1:{port}/"
        print(f"QQ 聊天记录导出器已启动: {url}  (关闭本窗口即退出工具)")
        if not args.no_browser:
            threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    else:
        if not args.no_browser:
            webbrowser.open(url)
        time.sleep(2)
        return
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
