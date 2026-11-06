# -*- coding: utf-8 -*-
"""用字符串交叉引用在已剥离符号的 .so 里定位 sqlite3_exec。

背景: 某些版本的 QQ 把 SQLCipher 编进 libkernel.so 并且剥掉了符号表, 按名字 hook
找不到。这个脚本靠「PRAGMA journal_mode;」「sqlcipher_export」这类字符串反查调用点。

注: 本仓库实测的那一版, SQLCipher 其实在 libbasic_share.so 且符号仍在(改名为
nt_sqlite3_*), 不需要这个脚本。留在这里是为了应对"换版本后找不到符号"的情况。

用法:
    python analyze_libkernel.py libkernel.so
依赖:
    pip install capstone pyelftools
"""
import re
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

ANCHORS = [b"PRAGMA journal_mode;", b"PRAGMA cipher_version;", b"sqlcipher_export",
           b"PRAGMA key", b"PRAGMA rekey"]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]

    with open(path, "rb") as f:
        data = f.read()

    elf = ELFFile(open(path, "rb"))
    sections = []
    for s in elf.iter_sections():
        if s.data_size == 0:
            continue
        sections.append((s.name, s["sh_addr"], s["sh_size"], s["sh_flags"], s.data_size))

    def file_off_to_vaddr(off):
        for name, addr, size, flags, dsize in sections:
            s = elf.get_section_by_name(name)
            if s["sh_type"] == "SHT_NOBITS":
                continue
            start = s["sh_offset"]
            end = start + s.data_size
            if start <= off < end:
                return addr + (off - start)
        return None

    def vaddr_to_file(vaddr):
        for name, addr, size, flags, dsize in sections:
            if addr <= vaddr < addr + size:
                s = elf.get_section_by_name(name)
                if s["sh_type"] == "SHT_NOBITS":
                    return None
                return s["sh_offset"] + (vaddr - addr)
        return None

    text_secs = [(n, a, sz) for (n, a, sz, fl, _) in sections if fl & 0x4]
    print("可执行段:", [(n, hex(a), sz) for n, a, sz in text_secs])

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    for anchor in ANCHORS:
        hits = [m.start() for m in re.finditer(re.escape(anchor), data)]
        print("\n=== 字符串 %r 命中 %d 处 ===" % (anchor, len(hits)))
        for off in hits[:4]:
            va = file_off_to_vaddr(off)
            print("  文件偏移 0x%x -> 虚拟地址 0x%x" % (off, va or 0))
            if not va:
                continue
            pat = va.to_bytes(8, "little")
            refs = []
            for m in re.finditer(re.escape(pat), data):
                ref_va = file_off_to_vaddr(m.start())
                if ref_va and any(a <= ref_va < a + sz for _, a, sz in text_secs):
                    refs.append(("literal", ref_va))
            page = va >> 12
            for name, addr, size in text_secs:
                off0 = vaddr_to_file(addr)
                if off0 is None:
                    continue
                code = data[off0:off0 + size]
                last_adrp = None
                for ins in md.disasm(code, addr):
                    if ins.mnemonic == "adrp":
                        last_adrp = ins
                    elif ins.mnemonic == "add" and last_adrp is not None:
                        ops = ins.operands
                        if len(ops) >= 3 and ops[2].type == ARM64_OP_IMM:
                            target = (last_adrp.operands[1].imm if len(last_adrp.operands) > 1 else 0) + ops[2].imm
                            if target == va:
                                refs.append(("adrp+add", ins.address))
                    if ins.address - (last_adrp.address if last_adrp else ins.address) > 40:
                        last_adrp = None
            print("  引用点 %d 个: %s" % (len(refs), [(k, hex(v)) for k, v in refs[:8]]))
            for kind, ref_va in refs[:3]:
                print("  --- 反汇编 0x%x 附近 ---" % ref_va)
                off0 = vaddr_to_file(ref_va - 64)
                code = data[off0:off0 + 220]
                for ins in md.disasm(code, ref_va - 64):
                    print("    %x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
