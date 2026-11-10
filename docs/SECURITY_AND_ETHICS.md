# X-Ray Binary — Security, Safety and Ethics

## 1. Position
X-Ray Binary is a **defensive** tool. It never executes samples, never generates or modifies malware, and publishes no weaponisable artefacts.

## 2. Threat Model

| Asset | Threat | Control |
|---|---|---|
| Host running analysis | Exploit in parser/disassembler (radare2, LIEF, pefile) via crafted binary | Ephemeral container per job; `--network none`; read-only root; `tmpfs` workdir; `--cap-drop ALL`; `no-new-privileges`; seccomp; non-root UID; cgroup CPU/mem/pids limits; hard timeout; optional gVisor |
| Host | Decompression bombs / huge inputs | Upload cap, function cap, output-size caps, wall-clock timeouts |
| Other users' data | Cross-sample leakage | Per-job isolated workdir; content-addressed storage; no shared mutable state |
| Analysts | Malicious strings/disassembly rendered in UI (XSS) | Escape all untrusted text; CSP; no `dangerouslySetInnerHTML`; length caps |
| Service | Abuse/DoS | Rate limits, queue depth caps, API keys in hosted mode |
| Integrity | Poisoned reference corpus or model files | Hash-manifested, read-only model bundles; signed releases (stretch) |
| Confidentiality | Exfiltration of uploaded files | No outbound network from workers; no third-party calls; delete endpoint |
| Model | Adversarial evasion by graph-aware attacker | Documented limitation; augmentation, ensemble depths; roadmap adversarial training |

## 3. Safe Handling of Malware Samples
- Store and analyse on an isolated machine/VM without credentials or shared folders.
- Keep samples in archives with the conventional `infected` password when moving; never double-click.
- Share **hashes and derived graphs**, not binaries.
- Follow the dataset provider's terms (e.g., MalwareBazaar/BODMAS access conditions).
- Never test on production endpoints.

## 4. Responsible Evasion Research
The Evasion Lab transforms **benign programs from source** with standard compiler/obfuscator toolchains. It does not integrate or output tooling that evades detection for malware; it measures how robust a *detector* is. Real malware appears only as pre-existing, publicly available research samples in the isolated evaluation environment. No new evasion technique is introduced; transformations are widely documented academic/industry obfuscations.

## 5. Dual-Use Assessment
| Risk | Assessment | Mitigation |
|---|---|---|
| Attackers use our results to evade | Retention numbers reveal which transformations hurt most | Report robustly and openly; publishing defensive limitations is standard practice; no evasion code for malware |
| Misclassification harms users (false positive) | Triage tool; human in the loop | Calibrated confidence, evidence, thresholds tuned for FPR, "suspicious" tier |
| Over-trust in ML | Black-box risk | Explainability, honest limitation banners |

## 6. Privacy
Local-first; no telemetry; uploads deletable; logs contain hashes, not file contents; configurable retention TTL.

## 7. Compliance Notes
Respect dataset licences; track third-party licences (radare2 LGPL, UPX GPL-with-exception, etc.); no personal data processed beyond uploaded files.

## 8. Security Test Plan
| Test | Expected |
|---|---|
| Truncated/garbage PE/ELF | Job fails cleanly, container destroyed, no hang |
| Header with absurd section counts/sizes | Timeout or cap triggers, `partial_analysis` |
| Network attempt from sandbox | Blocked (verified by test) |
| Write outside workdir | Fails (read-only FS) |
| XSS payload in section/function names | Rendered as inert text |
| Oversized upload | `413` |
| Resource exhaustion | cgroup kills job; API stays healthy |

## 9. Operational Guidance
Patch radare2 promptly (pin + update cadence), rebuild sandbox images regularly, rotate API keys, monitor `xray_r2_timeouts_total` and container kills as potential exploit indicators.
