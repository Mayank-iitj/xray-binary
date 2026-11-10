# X-Ray Binary — UI/UX Specification

## 1. Design Principles
1. **Evidence first.** Every verdict sits next to *why*.
2. **Progressive disclosure.** Verdict → evidence list → graph → disassembly.
3. **Honest states.** Packed/partial/truncated are loud, never hidden.
4. **Analyst speed.** Keyboard-driven, no modal traps, 5-second comprehension on the report page.
5. **Safe by default.** Untrusted strings are escaped; nothing is executed or auto-opened.

## 2. Visual Language ("X-ray" theme)

| Token | Value | Use |
|---|---|---|
| `--bg` | `#0B0F14` | App background |
| `--panel` | `#121821` | Cards |
| `--border` | `#1E2733` | Dividers |
| `--text` | `#E6EDF3` / muted `#8B98A5` | Text |
| `--accent` | `#22D3EE` (cyan) | Primary, selection glow |
| `--danger` | `#F43F5E` | Malicious / high suspicion |
| `--warn` | `#F59E0B` | Suspicious / packed |
| `--safe` | `#10B981` | Benign |
| Node ramp | cool-grey → amber → red (perceptually uniform) | Suspicion score |
Typography: Inter (UI), JetBrains Mono (addresses, disassembly). Light theme supported via tokens.
Accessibility: colour is never the only channel — suspicion also encoded by **node size/halo** and text labels; WCAG AA contrast; `prefers-reduced-motion` disables auto-rotation.

## 3. Information Architecture

```
/                   Upload + recent analyses
/a/[analysisId]     Report (tabs: Overview · Graph · Evidence · Obfuscation · Raw JSON)
/compare            Two analyses side by side, graph diff
/lab                Evasion Lab
/benchmarks         Metrics, baselines, ablations
/families           Family explorer (top motifs per family)
/about              Method, limitations, ethics
```

## 4. Key Screens

### 4.1 Upload (`/`)
Drag-and-drop zone; format hint (PE/ELF ≤ 50 MB); toggle "attempt static unpack"; banner "Static analysis only — files are never executed." Recent analyses list with verdict chips.

### 4.2 Analysis Progress
Stage stepper driven by SSE (Intake → Triage → Disassembly → Graph → Fingerprint → Model → Evidence → Obfuscation). Live timings. Cancel button. On failure: reason + what partial results exist.

### 4.3 Report — Overview tab
```
┌───────────────────────────────────────────────────────────────────────────────┐
│ [MALICIOUS 96%]  family: ransomware        sample sha256 · PE64 · 1.8 MB       │
│ "14 functions share ransomware-specific structure: enumerate→crypto→write-back"│
├───────────────┬───────────────────────────────┬──────────────────────────────┤
│ Family sim.   │ Scorers                        │ Flags                         │
│ ransomware ██▉│ WL kernel   0.88               │ ⚠ CFF in 2 functions          │
│ keylogger  ██ │ GNN         0.93               │ ⚠ XOR decode routine          │
│ downloader █▌ │ Agreement:  ✔ high             │ ✔ not packed                  │
│ benign     █  │                                │                              │
├───────────────┴───────────────────────────────┴──────────────────────────────┤
│ Top evidence (click → focus in graph)                                          │
│ 1 0x140012a40  0.97  file+crypto   "seen in 71% ransomware refs / 0% benign"   │
│ 2 0x140010800  0.94  file          …                                           │
└───────────────────────────────────────────────────────────────────────────────┘
```
Verdict chip colours: malicious (red), suspicious (amber), inconclusive-packed (amber outline + banner), benign (green).

### 4.4 Graph tab — 3D force graph
- Nodes = functions; size = code size (log); colour = suspicion; halo = obfuscation badge; edges = calls (curved, low opacity, directional particles on hover).
- Controls: orbit/zoom/pan, **focus on evidence** (camera flies to top node), filter slider (min score), toggle clusters, search by address/API bucket, "2D mode" (accessibility + low-GPU), reset view.
- Hover tooltip: address, score, API buckets. Click → right-hand **Node Inspector**.
- Performance: render ≤ 2 000 nodes; LOD; cluster super-nodes for pruned regions; worker-thread layout warm-up; freeze physics after settle.
- Legend always visible: colour ramp, size, halo meaning.

### 4.5 Node Inspector
Tabs: *Why flagged* (motif stats, family vs benign document frequency, GNN occlusion agreement) · *Disassembly* (capped excerpt, escaped, mono) · *Neighbours* (callers/callees, click to navigate) · *CFG stats*. "Copy address" and "Open in radare2 command" helpers.

### 4.6 Obfuscation tab
Cards: Packing (section entropy bar chart, W+X, import sparsity), Control-flow flattening (function list with score and a mini CFG showing the dispatcher hub), XOR decode routines (loop blocks, key candidate if constant), Junk ratio. Each card has an **"Impact on analysis"** line (e.g., "structure reliable: yes").

### 4.7 Evasion Lab (`/lab`)
Left: choose benign program; checklist of transformations; run. Right: **waterfall chart** (retention per stage, with baseline lines overlaid), table of results (hash/YARA/TLSH/n-gram vs ours), **graph diff** view (reference vs selected variant, shared nodes in cyan, changed in amber). Toggle "after static unpack" for UPX stage. Cached results make the demo instant; "re-run live" available.

### 4.8 Benchmarks
Tabs: Overall (ROC, PR, TPR@FPR) · Per-family (confusion matrix) · LOFO · Baselines on evasion variants (grouped bars with CIs) · Ablations · Calibration · Failure cases. Each chart exportable as PNG/CSV; "How measured" drawer links to EVALUATION_PLAN.

### 4.9 Compare
Two reports side by side; WL cosine; shared/unique motifs; matched nodes list; graph diff.

## 5. States and Microcopy
| State | Copy |
|---|---|
| Packed, not unpacked | "This file looks packed. The graph below reflects the unpacker stub, so structural scores are unreliable." |
| Partial analysis | "Disassembly hit its time limit; results use the functions recovered so far." |
| Unknown family | "No close family match. Structurally unusual — review the obfuscation panel." |
| Scorers disagree | "WL and GNN disagree. Confidence reduced." |
| Unsupported format | "Supported: PE and ELF (x86/x64). .NET/Java/script payloads are out of scope." |

## 6. Interaction and Accessibility Checklist
Keyboard: `/` search, `j/k` next/prev evidence, `Enter` focus node, `g` toggle 2D/3D, `Esc` clear selection. ARIA live region for progress. Focus rings visible. Tooltips reachable by keyboard. Screen-reader summary of the verdict and top-3 evidence. Reduced-motion mode.

## 7. Frontend Architecture
Next.js app router; React Query for API/SSE; Zustand for selection state shared between evidence list, graph, inspector; `3d-force-graph` in a client component with dynamic import (no SSR); graph JSON streamed and parsed in a Web Worker; Recharts/Plotly for charts; Tailwind + shadcn/ui; Playwright smoke tests (upload → report → click node → inspector).

## 8. Demo-Mode Affordances
`?demo=1` loads pre-cached analyses (no backend latency), pre-selects the evidence node, and enables presenter shortcuts (`1`…`5` jump to tabs) and a laser-pointer cursor.
