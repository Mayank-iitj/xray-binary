"""Structural Node Labelling for Call Graphs & CFGs.

Crucial Property: Labels NEVER contain raw bytes, function names, strings, or absolute addresses.
Labels combine:
1. Instruction-class profile (decile-bucketed frequency of arithmetic, logic, stack, branches, calls, memory, xor)
2. Normalized API semantic buckets (file, crypto, net, process, input, registry, memory, loader, antidbg)
3. CFG topological metrics (cyclomatic complexity, basic block count buckets)
"""
from __future__ import annotations
import re
from typing import Dict, List, Set, Any

INSN_CLASSES = {
    # Data Movement
    "mov": "data", "movzx": "data", "movsx": "data", "lea": "data", "xchg": "data",
    # Stack Operations
    "push": "stack", "pop": "stack", "upush": "stack", "pushf": "stack", "popf": "stack",
    # Arithmetic
    "add": "arith", "sub": "arith", "mul": "arith", "imul": "arith", "div": "arith", "idiv": "arith",
    "inc": "arith", "dec": "arith", "neg": "arith",
    # Logic & Bitwise
    "and": "logic", "or": "logic", "not": "logic",
    # XOR (isolated for cryptography/decryption routines)
    "xor": "xor",
    # Shift / Rotate
    "shl": "shift", "shr": "shift", "sar": "shift", "sal": "shift", "rol": "shift", "ror": "shift",
    # Comparisons & Tests
    "cmp": "cmp", "test": "cmp",
    # Unconditional branches
    "jmp": "jmp",
    # Conditional branches
    "cjmp": "cjmp", "je": "cjmp", "jne": "cjmp", "jz": "cjmp", "jnz": "cjmp",
    "jg": "cjmp", "jge": "cjmp", "jl": "cjmp", "jle": "cjmp", "ja": "cjmp", "jae": "cjmp",
    "jb": "cjmp", "jbe": "cjmp", "js": "cjmp", "jns": "cjmp", "jo": "cjmp", "jno": "cjmp",
    # Calls & Returns
    "call": "call", "ucall": "call", "syscall": "call",
    "ret": "ret", "retn": "ret",
    # NOP / Dead code
    "nop": "nop",
    # Memory direct load/store
    "load": "mem", "store": "mem", "movsb": "mem", "movsd": "mem", "stosb": "mem", "stosd": "mem",
}

API_BUCKETS = {
    "file": [
        "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "FindFirstFile",
        "FindNextFile", "MoveFileEx", "SetFileAttributes", "GetFileSize",
        "CreateDirectory", "RemoveDirectory", "open", "read", "write", "unlink",
        "fopen", "fread", "fwrite", "fclose", "remove", "stat"
    ],
    "crypto": [
        "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
        "CryptCreateHash", "CryptHashData", "CryptDeriveKey", "BCryptEncrypt",
        "BCryptDecrypt", "BCryptGenerateSymmetricKey", "BCryptOpenAlgorithmProvider",
        "EVP_EncryptInit", "AES_encrypt", "RSA_public_encrypt", "MD5_Init", "SHA256_Init"
    ],
    "net": [
        "InternetOpen", "InternetOpenUrl", "URLDownloadToFile", "HttpSendRequest",
        "HttpOpenRequest", "InternetConnect", "InternetReadFile", "WSAStartup",
        "connect", "send", "recv", "socket", "gethostbyname", "WinHttpOpen",
        "WinHttpConnect", "WinHttpSendRequest", "curl_easy_init", "curl_easy_perform"
    ],
    "process": [
        "CreateProcess", "ShellExecute", "WinExec", "CreateRemoteThread",
        "VirtualAllocEx", "WriteProcessMemory", "OpenProcess", "TerminateProcess",
        "fork", "execve", "system", "popen", "ptrace"
    ],
    "input": [
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetForegroundWindow",
        "GetKeyboardState", "GetMessage", "RegisterHotKey", "GetClipboardData"
    ],
    "registry": [
        "RegSetValueEx", "RegCreateKeyEx", "RegOpenKeyEx", "RegQueryValueEx",
        "RegDeleteValue", "RegCloseKey", "RegEnumKeyEx"
    ],
    "memory": [
        "VirtualAlloc", "VirtualProtect", "HeapAlloc", "HeapCreate",
        "VirtualFree", "mmap", "mprotect", "malloc", "free"
    ],
    "loader": [
        "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
        "LdrLoadDll", "dlopen", "dlsym"
    ],
    "antidbg": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter"
    ],
}

_REVERSED_API_INDEX: Dict[str, str] = {}
for bucket_name, api_names in API_BUCKETS.items():
    for name in api_names:
        _REVERSED_API_INDEX[name.lower()] = bucket_name

def api_bucket(api_name: str) -> str | None:
    """Classifies an API symbol name into a semantic bucket regardless of dll prefixes or A/W/Ex suffixes."""
    if not api_name:
        return None
    # Strip dll prefix e.g. "kernel32!CreateFileW" or "lib.so.6:open"
    base = re.sub(r"^.*[!.:]", "", api_name).lstrip("_")
    # Normalize A/W/Ex suffixes
    base = re.sub(r"(Ex)?[AW]$", r"\1", base) if base.endswith(("A", "W")) else base
    # Check lowercase
    lowered = base.lower()
    if lowered in _REVERSED_API_INDEX:
        return _REVERSED_API_INDEX[lowered]
    # Check without trailing 'ex'
    no_ex = re.sub(r"ex$", "", lowered)
    if no_ex in _REVERSED_API_INDEX:
        return _REVERSED_API_INDEX[no_ex]
    return None

def extract_node_label(
    instruction_mnemonics: List[str],
    api_calls: Iterable[str],
    cyclomatic_complexity: int = 1,
    basic_block_count: int = 1,
) -> str:
    """Constructs the canonical structural label for a function node.

    Format: <profile_deciles>|api:<sorted_buckets>|cc:<cc_capped>|bb:<bb_bucket>
    """
    prof: Dict[str, int] = {}
    for mnemonic in instruction_mnemonics:
        mnemonic_clean = mnemonic.lower().strip()
        category = INSN_CLASSES.get(mnemonic_clean, "other")
        prof[category] = prof.get(category, 0) + 1

    total_ops = max(1, sum(prof.values()))
    # Bucket into deciles 0..9
    prof_deciles = ",".join(
        f"{cat}:{min(9, int(10 * count / total_ops))}"
        for cat, count in sorted(prof.items())
    )

    # Collect unique API semantic buckets
    buckets: Set[str] = set()
    for api_name in api_calls:
        b = api_bucket(api_name)
        if b:
            buckets.add(b)

    api_str = "+".join(sorted(buckets)) if buckets else "-"
    cc_capped = min(max(1, cyclomatic_complexity), 20)
    bb_bucket = min(max(1, basic_block_count // 4), 10)

    return f"{prof_deciles}|api:{api_str}|cc:{cc_capped}|bb:{bb_bucket}"

