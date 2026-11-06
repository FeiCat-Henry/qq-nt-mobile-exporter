/*
 * qq-nt-mobile-exporter —— 手机 QQ (NT 版) 数据库 → 明文副本
 * -----------------------------------------------------------------
 * 原理:
 *   安卓 QQ 的 SQLCipher 在 libbasic_share.so 里, 函数被改名并仍然"正常导出":
 *     nt_sqlite3_open / _open_v2 / _key / _key_v2 / _exec / _prepare_v2 / _close ...
 *   (libkernel.so 里那份符号被剥掉了, 按名字找不到, 不要往那边找)
 *
 *   库本身在标准 SQLCipher 之外还多一层 1024 字节扩展头, 所以「拿到 key 自己开库」
 *   会失败 (rc=26 file is not a database)。正确做法是借 QQ 自己的连接执行:
 *
 *     ATTACH DATABASE '<输出>' AS qqbk KEY '';
 *     SELECT sqlcipher_export('qqbk');
 *     DETACH DATABASE qqbk;
 *
 *   等价于让 QQ 用它的密钥帮我们导出一份明文库。全程不需要知道 key 原文。
 *
 * 用法: 见 mobile/run_frida_export.py
 * 产物: /sdcard/Android/data/com.tencent.mobileqq/files/qqplain/*.db
 */
'use strict';

function say(t) { try { send({ kind: 'log', text: String(t) }); } catch (e) {} }

/* 输出目录: 放在 QQ 自己的外部目录里, 属主最省事 */
var OUT_DIR = '/sdcard/Android/data/com.tencent.mobileqq/files/qqplain';

/* 提供 nt_sqlite3_* 的模块名(子串匹配, 不区分大小写) */
var PROVIDER = ['libbasic_share'];

/* 想导的库。fts 两个库是"有就导", 没有并不影响正文(正文在 nt_msg.db 里) */
var TARGETS = ['nt_msg.db', 'profile_info.db', 'group_info.db',
               'buddy_msg_fts.db', 'group_msg_fts.db'];

/* nt_db 目录留空 = 从已打开的 nt_msg.db 句柄自动反推;
 * 如果 QQ 还没打开过任何库, 可以手动填成 /data/data/com.tencent.mobileqq/databases/nt_db/nt_qq_<hash> */
var NT_DB_DIR = '';

var ptrSize = Process.pointerSize;
var hooked = {};
var openPaths = {};      // db handle -> path
var exported = {};       // db handle -> true
var doneNames = {};      // 库名 -> true
var probed = {};         // db handle -> 已尝试过探路
var busy = false;
var execFn = null;
var openFn = null;
var keyFn = null;
var closeFn = null;
var round = 0;

function baseName(p) {
    var a = String(p).split('/');
    return a[a.length - 1];
}

function isTarget(path) { return path && TARGETS.indexOf(baseName(path)) >= 0; }

function providerModule() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        var n = mods[i].name.toLowerCase();
        for (var j = 0; j < PROVIDER.length; j++) {
            if (n.indexOf(PROVIDER[j]) >= 0) return mods[i];
        }
    }
    return null;
}

function sym(mod, name) {
    try { var p = mod.findExportByName(name); if (p) return p; } catch (e) {}
    try { return Module.findExportByName(mod.name, name); } catch (e) { return null; }
}

function attach(name, addr, cbs) {
    var k = name + '@' + addr;
    if (hooked[k]) return false;
    hooked[k] = true;
    try { Interceptor.attach(addr, cbs); return true; }
    catch (e) { say('[hook失败] ' + k + ' ' + e); return false; }
}

function hexOf(ptrKey, n) {
    var hex = '';
    try {
        for (var i = 0; i < n; i++) {
            var v = ptrKey.add(i).readU8();
            hex += (v < 16 ? '0' : '') + v.toString(16);
        }
    } catch (e) {}
    return hex;
}

/* ---------- 导出 ---------- */
function doExport(db, name) {
    if (busy || !execFn) return;
    busy = true;
    var out = OUT_DIR + '/' + name;
    try {
        /* 同名旧文件先删, 否则 sqlcipher_export 会报 "table xxx already exists" */
        try { var f = new File(out, 'r'); if (f && f.unlink) f.unlink(); } catch (e2) {}

        var sql = Memory.allocUtf8String(
            "ATTACH DATABASE '" + out + "' AS qqbk KEY ''; " +
            "SELECT sqlcipher_export('qqbk'); " +
            "DETACH DATABASE qqbk;");
        var errp = Memory.alloc(ptrSize);
        errp.writePointer(ptr(0));
        var rc = execFn(db, sql, ptr(0), ptr(0), errp);

        if (rc === 0) {
            doneNames[name] = true;
            exported[db.toString()] = true;
            say('[成功] ' + name + ' -> ' + out);
        } else {
            var m = errp.readPointer();
            say('[失败] ' + name + ' rc=' + rc + (m.isNull() ? '' : ' ' + m.readCString()));
        }
    } catch (e) {
        say('[导出异常] ' + name + ' ' + e);
    }
    busy = false;
}

function tryExport(db) {
    if (busy || !db || db.isNull()) return;
    var hs = db.toString();
    var path = openPaths[hs];
    if (!path) {
        /* attach 模式下库可能在挂 hook 之前就打开了 → 用 PRAGMA database_list 问它自己 */
        if (!probed[hs]) { probed[hs] = true; probePath(db); }
        return;
    }
    if (exported[hs] || !isTarget(path)) return;
    var b = baseName(path);
    if (doneNames[b]) { exported[hs] = true; return; }
    doExport(db, b);
}

/* ---------- 句柄 → 路径 (PRAGMA database_list 的第 3 列就是文件名) ---------- */
var probeCb = new NativeCallback(function (arg, ncol, values, names) {
    try {
        if (ncol >= 3 && values && !values.isNull()) {
            var cell = values.add(2 * ptrSize).readPointer();
            if (!cell.isNull()) {
                var v = cell.readCString();
                if (v && v.length && v !== ':memory:') {
                    openPaths[arg.toString()] = v;
                    if (isTarget(v)) say('[发现] ' + baseName(v));
                }
            }
        }
    } catch (e) {}
    return 0;
}, 'int', ['pointer', 'int', 'pointer', 'pointer']);

function probePath(db) {
    if (busy || !execFn) return;
    busy = true;
    try {
        var sql = Memory.allocUtf8String('PRAGMA database_list;');
        var errp = Memory.alloc(ptrSize);
        errp.writePointer(ptr(0));
        execFn(db, sql, probeCb, db, errp);
    } catch (e) {
        say('[探路失败] ' + e);
    }
    busy = false;
}

/* ---------- 安装 ---------- */
function install(mod) {
    var execAddr = sym(mod, 'nt_sqlite3_exec');
    if (!execAddr) return false;
    if (!execFn) {
        execFn = new NativeFunction(execAddr, 'int',
            ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
        var pOpen = sym(mod, 'nt_sqlite3_open_v2') || sym(mod, 'nt_sqlite3_open');
        var pKey = sym(mod, 'nt_sqlite3_key');
        var pClose = sym(mod, 'nt_sqlite3_close');
        if (pOpen) openFn = new NativeFunction(pOpen, 'int', ['pointer', 'pointer', 'int', 'pointer']);
        if (pKey) keyFn = new NativeFunction(pKey, 'int', ['pointer', 'pointer', 'int']);
        if (pClose) closeFn = new NativeFunction(pClose, 'int', ['pointer']);
        say('[就绪] nt_sqlite3_exec @ ' + execAddr);
    }

    /* 打开文件 → 记 句柄 → 路径 */
    [['nt_sqlite3_open', 2], ['nt_sqlite3_open_v2', 2]].forEach(function (spec) {
        var p = sym(mod, spec[0]);
        if (!p) return;
        attach(spec[0], p, {
            onEnter: function (args) { this.fn = args[0]; this.pp = args[1]; },
            onLeave: function (ret) {
                try {
                    if (this.fn.isNull() || this.pp.isNull()) return;
                    var db = this.pp.readPointer();
                    if (db.isNull()) return;
                    var path = this.fn.readCString();
                    var hs = db.toString();
                    if (path && openPaths[hs] !== path) {
                        openPaths[hs] = path;
                        say('[打开] ' + baseName(path));
                    }
                } catch (e) {}
            }
        });
    });

    /* 设置密钥 → 记 key(备份用), 并趁机导出 */
    [['nt_sqlite3_key', 2], ['nt_sqlite3_key_v2', 3]].forEach(function (spec) {
        var p = sym(mod, spec[0]);
        if (!p) return;
        attach(spec[0], p, {
            onEnter: function (args) {
                var idx = spec[1];
                this.db = args[0];
                try {
                    var n = args[idx].toInt32();
                    var k = args[idx - 1];
                    if (n >= 8 && n <= 200 && !k.isNull()) {
                        say('[密钥] ' + spec[0] + ' len=' + n + ' hex=' + hexOf(k, n));
                    }
                } catch (e) {}
            },
            onLeave: function () { try { tryExport(this.db); } catch (e) {} }
        });
    });

    /* 兜底: 任何 SQL 执行/预编译都试一次 */
    ['nt_sqlite3_exec', 'nt_sqlite3_prepare_v2'].forEach(function (name) {
        var p = sym(mod, name);
        if (!p) return;
        attach(name, p, {
            onEnter: function (args) { this.db = args[0]; },
            onLeave: function () { try { tryExport(this.db); } catch (e) {} }
        });
    });

    return true;
}

function scan() {
    round++;
    try {
        var mod = providerModule();
        if (mod) install(mod);
    } catch (e) { say('[扫描异常] ' + e); }

    var got = Object.keys(doneNames).length;
    if (got >= TARGETS.length) { say('[完成] ' + got + '/' + TARGETS.length); return; }
    if (round <= 3 && execFn) {
        say('[扫描] 第 ' + round + ' 轮, ' + Object.keys(openPaths).length +
            ' 个句柄, 已导出 ' + got + '/' + TARGETS.length);
    }
    setTimeout(scan, 1000);
}

say('[启动] 等待 ' + PROVIDER.join('/') + ' 加载 ... (库目录: ' + (NT_DB_DIR || '自动') + ')');
setTimeout(scan, 200);
