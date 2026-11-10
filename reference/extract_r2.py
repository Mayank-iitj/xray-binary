"""radare2 -> structural graph extractor (REFERENCE SKELETON).

STATUS: logic follows documented r2 JSON commands (aflj, afbj, pdfj, iij, iSj), but this file was NOT
run against a live radare2 in the authoring environment. Verify field names against your pinned r2
version on day 1 (see docs/ROADMAP_AND_RISKS.md, task D1-02). Run ONLY inside the analysis sandbox.
"""
from __future__ import annotations
import re, r2pipe

INSN_CLASSES = {  # r2 op "type" -> coarse instruction class (labels never contain raw bytes/names)
    "mov": "data", "lea": "data", "push": "stack", "pop": "stack", "upush": "stack",
    "add": "arith", "sub": "arith", "mul": "arith", "div": "arith", "inc": "arith", "dec": "arith",
    "and": "logic", "or": "logic", "xor": "logic", "not": "logic", "shl": "shift", "shr": "shift",
    "rol": "shift", "ror": "shift", "cmp": "cmp", "test": "cmp", "jmp": "jmp", "cjmp": "cjmp",
    "call": "call", "ucall": "call", "ret": "ret", "nop": "nop", "load": "mem", "store": "mem",
}
API_BUCKETS = {  # normalised import name (A/W suffix + lib prefix stripped) -> semantic bucket
    "file":    ["CreateFile", "ReadFile", "WriteFile", "DeleteFile", "FindFirstFile", "FindNextFile", "MoveFileEx", "open", "read", "write", "unlink"],
    "crypto":  ["CryptAcquireContext", "CryptEncrypt", "CryptGenKey", "BCryptEncrypt", "BCryptGenerateSymmetricKey", "EVP_EncryptInit", "AES_encrypt"],
    "net":     ["InternetOpen", "InternetOpenUrl", "URLDownloadToFile", "HttpSendRequest", "WSAStartup", "connect", "send", "recv", "socket", "WinHttpOpen"],
    "process": ["CreateProcess", "ShellExecute", "WinExec", "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "OpenProcess", "fork", "execve"],
    "input":   ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetForegroundWindow", "GetKeyboardState"],
    "registry":["RegSetValueEx", "RegCreateKeyEx", "RegOpenKeyEx"],
    "memory":  ["VirtualAlloc", "VirtualProtect", "HeapAlloc", "mmap", "mprotect"],
    "loader":  ["LoadLibrary", "GetProcAddress", "dlopen", "dlsym"],
    "antidbg": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "ptrace"],
}
_REV = {n.lower(): b for b, names in API_BUCKETS.items() for n in names}

def api_bucket(name: str) -> str | None:
    base = re.sub(r"^.*[!.]", "", name).lstrip("_")
    base = re.sub(r"(Ex)?[AW]$", r"\1", base) if base[-1:] in "AW" else base
    for cand in (base.lower(), re.sub(r"ex$", "", base.lower())):
        if cand in _REV: return _REV[cand]
    return None

def extract(path: str, max_funcs: int = 20000) -> dict:
    r = r2pipe.open(path, flags=["-2"])           # -2: silence stderr
    try:
        r.cmd("aaa")                               # full analysis; caller enforces wall-clock timeout
        funcs = r.cmdj("aflj") or []
        if len(funcs) > max_funcs: funcs = sorted(funcs, key=lambda f: -f.get("size", 0))[:max_funcs]
        by_addr = {f["offset"]: f for f in funcs}
        nodes, edges, cfgs = {}, [], {}
        for f in funcs:
            fid = hex(f["offset"])
            ops = (r.cmdj(f"pdfj @ {f['offset']}") or {}).get("ops", [])
            prof, apis = {}, set()
            for op in ops:
                c = INSN_CLASSES.get(op.get("type"), "other"); prof[c] = prof.get(c, 0) + 1
                if op.get("type") in ("call", "ucall"):
                    b = api_bucket((op.get("disasm") or "").split()[-1]) if op.get("disasm") else None
                    if b: apis.add(b)   # verify: imported-call symbol naming differs per r2 version/format
            n = max(1, sum(prof.values()))
            prof_label = ",".join(f"{k}:{min(9, int(10 * v / n))}" for k, v in sorted(prof.items()))   # decile-bucketed
            cc, nbbs = f.get("cc", 0), f.get("nbbs", 0)
            label = f"{prof_label}|api:{'+'.join(sorted(apis)) or '-'}|cc:{min(cc, 20)}|bb:{min(nbbs // 4, 10)}"
            nodes[fid] = label
            for cr in f.get("callrefs", []) or []:
                if cr.get("type") == "CALL" and cr["addr"] in by_addr: edges.append((fid, hex(cr["addr"])))
            bbs = r.cmdj(f"afbj @ {f['offset']}") or []
            cfgs[fid] = {"entry": hex(f["offset"]),
                         "blocks": {hex(b["addr"]): [(o.get("type", "?"), o.get("disasm", "")) for o in
                                    (r.cmdj(f"pdj {b.get('ninstr', 0)} @ {b['addr']}") or [])] for b in bbs},
                         "edges": [(hex(b["addr"]), hex(t)) for b in bbs for t in (b.get("jump"), b.get("fail")) if t]}
        return {"nodes": nodes, "edges": edges, "cfgs": cfgs,
                "sections": r.cmdj("iSj") or [], "imports": r.cmdj("iij") or [], "info": r.cmdj("ij") or {}}
    finally:
        r.quit()
