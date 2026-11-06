"""批量导出手机 QQ（NT 版）明文库里的全部会话。

前置：已经用 frida-qq-nt-export.js 把 nt_msg.db / profile_info.db / group_info.db
导成明文并 pull 到本地目录。

用法:
    python export_all.py --nt-dir qqplain --out out_mobile
    python export_all.py --nt-dir qqplain --out out_txt --fmt txt
"""
import argparse
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qq_exporter as q


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nt-dir", required=True, help="含 nt_msg.db 的明文目录")
    ap.add_argument("--out", default="out_mobile", help="输出目录")
    ap.add_argument("--fmt", default="html", choices=["html", "txt", "csv"])
    ap.add_argument("--uin", default="10000", help="展示用的账号号(仅影响页脚)")
    ap.add_argument("--only", default="", help="只导这些会话 key, 逗号分隔")
    args = ap.parse_args()

    root = os.path.abspath(args.nt_dir)
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)

    q.LOCAL_DB_DIR = root
    q.LOCAL_KEY = None
    q.LOCAL_UIN = args.uin

    res = q.list_conversations(None, args.uin, {}, False, lambda m, p=0: None)
    convs = res["conversations"]
    if args.only:
        want = {k.strip() for k in args.only.split(",") if k.strip()}
        convs = [c for c in convs if c["key"] in want]
    print(f"会话 {len(convs)} 个, 输出到 {out}")

    nt = os.path.join(root, "nt_msg.db")
    ok, total, fails = 0, 0, []
    t0 = time.time()
    for i, c in enumerate(convs, 1):
        s = {"kind": c["kind"], "key": c["key"], "uin": c.get("uin"), "name": c.get("name")}
        con = sqlite3.connect(nt)
        try:
            info = q.export_one(con, None, args.uin, s, args.fmt, out, {}, None, None,
                                lambda m, p=0: None)
            ok += 1
            total += info["count"]
            print(f"[{i}/{len(convs)}] {info['name'] or c['key']} -> {info['count']} 条")
        except Exception as e:
            fails.append((c.get("name") or c["key"], str(e)[:80]))
            print(f"[{i}/{len(convs)}] 跳过 {c.get('name') or c['key']}: {e}")
        finally:
            con.close()

    print(f"\n完成: {ok}/{len(convs)} 个会话, 共 {total} 条消息, 耗时 {time.time() - t0:.0f}s")
    if fails:
        print("失败清单:")
        for n, e in fails:
            print("   ", n, e)


if __name__ == "__main__":
    main()
