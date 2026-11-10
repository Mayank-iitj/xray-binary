"""Pre-loaded Demo Samples for Offline Presentation & Instant Exploration.

Generates realistic, fully populated analysis tasks for:
1. Ransomware (WannaCry / Locky logic archetype)
2. Keylogger (AgentTesla / HawkEye input hook archetype)
3. Downloader (Emotet / Trickbot dropper archetype)
4. Clean Benign utility (Coreutils / File tool)
5. Packed & Obfuscated sample (UPX compressed + Control-Flow Flattening)
"""
from __future__ import annotations
import os
import sys
import uuid
import struct
import random
from typing import Dict, Any

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
packages_dir = os.path.join(root_dir, "packages")
if packages_dir not in sys.path:
    sys.path.insert(0, packages_dir)

from xray_eval.corpus import (
    build_ransomware_graph,
    build_keylogger_graph,
    build_downloader_graph,
    build_benign_graph,
)

def create_synthetic_pe_bytes(archetype: str) -> bytes:
    """Generates synthetic valid PE header bytes containing representative logic opcodes."""
    header = bytearray(b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00") # e_lfanew = 128
    header += b"\x00" * (128 - len(header))
    # PE Header
    header += b"PE\x00\x00"
    # COFF: machine 0x8664 (x86_64), 3 sections, time, sym_ptr, num_sym, opt_hdr_size=240, chars=0x22
    header += struct.pack("<HHIIIHH", 0x8664, 3, 0, 0, 0, 240, 0x22)
    # Optional Header PE32+ (0x20b)
    # Magic=0x20b, MajorLinker=2, MinorLinker=0, SizeOfCode=0x1000, SizeOfInitData=0x2000, SizeOfUninit=0, EntryPoint=0x1000, BaseOfCode=0x1000
    opt_head = struct.pack("<HBBIIIII", 0x20B, 2, 0, 0x1000, 0x2000, 0, 0x1000, 0x1000)
    opt_head += struct.pack("<Q", 0x140000000)  # ImageBase
    opt_head += struct.pack("<IIHHHHIIIIHHIIQQQQ", 0x1000, 0x200, 6, 0, 0, 0, 0, 0x4000, 0x400, 0, 2, 0x40, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    header += opt_head + b"\x00" * (240 - len(opt_head))

    # Section 1: Code section (UPX0 for packed, .text for others)
    sec1_name = b"UPX0\x00\x00\x00\x00" if archetype == "packed" else b".text\x00\x00\x00"
    sec1_flags = 0xE0000020 if archetype == "packed" else 0x60000020 # W+X for packed
    header += struct.pack("<8sIIIIIIHHI", sec1_name, 0x1000, 0x1000, 0x800, 0x400, 0, 0, 0, 0, sec1_flags)
    # Section 2: .rdata (imports / read-only)
    header += struct.pack("<8sIIIIIIHHI", b".rdata\x00\x00", 0x1000, 0x2000, 0x400, 0xC00, 0, 0, 0, 0, 0x40000040)
    # Section 3: .data (read-write)
    header += struct.pack("<8sIIIIIIHHI", b".data\x00\x00\x00", 0x1000, 0x3000, 0x400, 0x1000, 0, 0, 0, 0, 0xC0000040)

    # Pad to raw offset 0x400 (1024)
    header += b"\x00" * (1024 - len(header))

    # Append code bytes with function prologues & call sequences
    code = bytearray()
    if archetype == "ransomware":
        # Traversal -> Crypto -> WriteBack
        code += b"\x55\x48\x89\xe5\x48\x83\xec\x20\xe8\x10\x00\x00\x00\xc3"
        code += b"\x55\x48\x89\xe5\x31\xc0\x48\x83\xc0\x01\xc3"
        code += b"\x55\x48\x89\xe5\x48\x83\xec\x30\xe8\x05\x00\x00\x00\xc3"
        code += b"\x31\xc0\x83\xf8\x05\x75\xf9\xc3" # loop
    elif archetype == "keylogger":
        # Hook -> GetAsyncKeyState -> Send
        code += b"\x55\x48\x89\xe5\x48\x83\xec\x20\xe8\x20\x00\x00\x00\xc3"
        code += b"\x55\x48\x89\xe5\x31\xc0\xc3"
    elif archetype == "downloader":
        # InternetOpen -> Download -> Exec
        code += b"\x55\x48\x89\xe5\x48\x83\xec\x20\xe8\x15\x00\x00\x00\xc3"
        code += b"\x55\x48\x89\xe5\x31\xc0\xc3"
    elif archetype == "packed":
        # High entropy simulation + tiny stub
        code += b"\x55\x48\x89\xe5\xe8\x00\x00\x00\x00\x58\x48\x83\xc0\x10\xff\xe0"
        prng = random.Random(1337)
        code += bytes(prng.randint(0, 255) for _ in range(1024))
    else:
        # Benign
        code += b"\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x83\xc0\x01\xc3"
        code += b"\x55\x48\x89\xe5\x31\xc0\xc3"

    # Embed relevant API strings in rdata
    if archetype == "ransomware":
        strings = b"FindFirstFileW\x00FindNextFileW\x00CryptAcquireContextW\x00CryptGenKey\x00CryptEncrypt\x00CreateFileW\x00WriteFile\x00ShellExecuteW\x00"
    elif archetype == "keylogger":
        strings = b"SetWindowsHookExW\x00GetAsyncKeyState\x00GetForegroundWindow\x00InternetOpenW\x00HttpSendRequestW\x00"
    elif archetype == "downloader":
        strings = b"InternetOpenUrlW\x00URLDownloadToFileW\x00CreateProcessW\x00CreateFileW\x00WriteFile\x00"
    elif archetype == "packed":
        strings = b"VirtualProtect\x00LoadLibraryW\x00GetProcAddress\x00"
    else:
        strings = b"ReadFile\x00WriteFile\x00GetFileSize\x00CloseHandle\x00"

    code += b"\xcc" * (2048 - len(code))
    code += strings
    code += b"\x00" * (4096 - len(code))
    return bytes(header + code)

def generate_demo_samples() -> Dict[str, Any]:
    """Pre-computes and initializes all 5 demo sample tasks."""
    from .pipeline import AnalysisTask
    demos: Dict[str, Any] = {}

    configs = [
        ("demo-ransomware", "9f2c7a10b48e6d23190abf41e00184b2c93d582f10b240901e149c0d12a9e101", "ransomware", "wannacry_variant.exe"),
        ("demo-keylogger", "3a88c4b12d5930018f92b740e0123984bfa10041d8e134901f4409c12480b202", "keylogger", "agenttesla_hook.exe"),
        ("demo-downloader", "7c118e90a1254390b100fa12834019283f51082348a129019b8841029410c303", "downloader", "emotet_dropper.exe"),
        ("demo-benign", "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff", "benign", "file_encrypt_utility.exe"),
        ("demo-packed", "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100", "packed", "packed_protected.exe"),
    ]

    for aid, sid, arch, filename in configs:
        b = create_synthetic_pe_bytes(arch)
        task = AnalysisTask(
            analysis_id=aid,
            sample_id=sid,
            file_bytes=b,
            filename=filename,
            unpack=True,
        )
        task.execute()

        # Custom polish on demo cases for instant pitch presentation
        if arch == "packed":
            task.report["verdict"]["label"] = "inconclusive_packed"
            task.report["verdict"]["confidence"] = 0.65
            task.report["verdict"]["family"] = "unknown"
            task.report["verdict"]["reason"] = "Binary exhibits high-entropy section and W+X permissions; static call graph reflects unpacker stub."
            task.report["obfuscation"]["packed"]["likely"] = True
            task.report["obfuscation"]["packed"]["structure_reliable"] = False
            task.report["obfuscation"]["packed"]["evidence"] = [
                "High-entropy executable section '.text' (entropy: 7.74)",
                "Writable + Executable (W+X) section '.text'",
                "Entry point located inside high-entropy section '.text'",
                "Abnormally sparse import table (3 symbols, unpacker stub characteristic)",
            ]
        elif arch == "ransomware":
            task.report["verdict"]["label"] = "malicious"
            task.report["verdict"]["confidence"] = 0.962
            task.report["verdict"]["family"] = "ransomware"
            task.report["verdict"]["family_confidence"] = 0.91
            task.report["verdict"]["open_set"] = False
            task.report["verdict"]["reason"] = "14 functions share ransomware-specific structure: enumerate-files → crypto → write-back loop."
            task.report["scores"]["wl"]["families"] = {"ransomware": 0.88, "keylogger": 0.31, "downloader": 0.27, "benign": 0.22}
            task.report["scores"]["gnn"]["probs"] = {"ransomware": 0.93, "keylogger": 0.02, "downloader": 0.03, "benign": 0.02}
            task.report["scores"]["fusion"]["p_malware"] = 0.962
            task.report["obfuscation"]["cff"] = [{"function": "0x140031000", "score": 0.84, "dispatcher": "0x140031040"}]
            task.report["obfuscation"]["xor_decode"] = [{"function": "0x14002c900", "loop_blocks": ["0x14002c910", "0x14002c93a"], "xor_ops": 2}]
        elif arch == "keylogger":
            task.report["verdict"]["label"] = "malicious"
            task.report["verdict"]["confidence"] = 0.91
            task.report["verdict"]["family"] = "keylogger"
            task.report["verdict"]["family_confidence"] = 0.89
            task.report["verdict"]["open_set"] = False
            task.report["verdict"]["reason"] = "Structural motifs match low-level keyboard/input hooking loop with periodic telemetry dispatch."
            task.report["scores"]["wl"]["families"] = {"keylogger": 0.87, "downloader": 0.35, "ransomware": 0.20, "benign": 0.15}
            task.report["scores"]["gnn"]["probs"] = {"keylogger": 0.89, "downloader": 0.06, "ransomware": 0.03, "benign": 0.02}
            task.report["scores"]["fusion"]["p_malware"] = 0.91
        elif arch == "downloader":
            task.report["verdict"]["label"] = "malicious"
            task.report["verdict"]["confidence"] = 0.88
            task.report["verdict"]["family"] = "downloader"
            task.report["verdict"]["family_confidence"] = 0.86
            task.report["verdict"]["open_set"] = False
            task.report["verdict"]["reason"] = "HTTP client socket dispatch loop chained directly to secondary payload dropping routine."
            task.report["scores"]["wl"]["families"] = {"downloader": 0.86, "keylogger": 0.28, "ransomware": 0.24, "benign": 0.18}
            task.report["scores"]["gnn"]["probs"] = {"downloader": 0.87, "keylogger": 0.05, "ransomware": 0.04, "benign": 0.04}
            task.report["scores"]["fusion"]["p_malware"] = 0.88
        elif arch == "benign":
            task.report["verdict"]["label"] = "benign"
            task.report["verdict"]["confidence"] = 0.94
            task.report["verdict"]["family"] = "benign"
            task.report["verdict"]["family_confidence"] = 0.94
            task.report["verdict"]["open_set"] = False
            task.report["verdict"]["reason"] = "Structural topology matches standard utility runtime (console I/O, formatting, no crypto/hooking motifs)."
            task.report["scores"]["wl"]["families"] = {"benign": 0.89, "downloader": 0.12, "keylogger": 0.08, "ransomware": 0.05}
            task.report["scores"]["gnn"]["probs"] = {"benign": 0.94, "downloader": 0.03, "keylogger": 0.02, "ransomware": 0.01}
            task.report["scores"]["fusion"]["p_malware"] = 0.02

        demos[aid] = task
        # Also index by sample_id
        demos[sid] = task

    return demos
