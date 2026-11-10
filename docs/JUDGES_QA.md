# Anticipated Judge Questions — Prepared Answers

Answer style: short, honest, with the evidence slide/page. Numbers must come from `make eval`; where this sheet says "[measured]" insert the actual value.

**1. Isn't this just another ML malware classifier?**
No: the representation is the contribution. Labels are structure-only (instruction-class profile + API semantics + CFG buckets), chosen so renaming, string encryption and repacking leave the fingerprint intact. We combine a training-free WL kernel with a GNN, expose node-level evidence, and quantify robustness with an Evasion Lab and baselines.

**2. What about packed malware?**
A packed binary's static graph is the unpacker stub. We detect packing (entropy, W+X, tiny imports), statically unpack known packers (UPX), and otherwise return `inconclusive_packed` with the reason. We don't claim to solve arbitrary packers statically; roadmap includes safe, isolated unpacking research.

**3. Compiler optimisation changes the call graph. Doesn't that break you?**
It reduces retention for inlining-heavy builds; we report retention per -O level [measured] and train with structure-preserving augmentation. High-level API/semantic motifs persist better than raw topology — see the ablation without API buckets.

**4. Control-flow flattening?**
It changes per-function CFG, not the call graph. Our node labels use coarse CFG buckets, and a dedicated detector flags the dispatcher pattern. Retention under OLLVM `-fla` is [measured] and shown, including where it drops.

**5. How do you avoid dataset leakage?**
Near-duplicate removal (TLSH / function-set Jaccard) before splitting, time-based splits, leave-one-family-out, grouped CV. Evaluation transformations are held out from training augmentation.

**6. How big is your dataset?**
[N] malware across [3] families and [M] benign, de-duplicated; counts and sources in the benchmark appendix. We state the scale honestly; the pipeline scales linearly with disassembly.

**7. Why not dynamic analysis?**
Dynamic analysis is powerful but slow, evaded by sandbox-aware malware, and risky/infra-heavy. Static structural triage is fast, safe, offline, and complementary.

**8. Why radare2 and not Ghidra/IDA?**
Free, scriptable, JSON output, headless, PE+ELF multi-arch, quick start. Ghidra has a better decompiler but heavier startup; our representation doesn't need decompilation. The extractor is behind an interface so Ghidra can be swapped in.

**9. How do you explain a GNN decision?**
Primary explanation comes from the WL fingerprint: per-label log-odds family vs benign, mapped to nodes — it is faithful to the scorer actually used. GNN occlusion is a cross-check. We measure faithfulness (drop in score when removing evidence nodes vs random nodes).

**10. False positives on benign software?**
Reported as FPR on system binaries and installers at the operating threshold; calibrated probabilities; "suspicious" tier; failure analysis lists the top false-positive causes (e.g., statically linked crypto libraries, installers).

**11. Can an attacker evade you?**
A graph-aware adaptive attacker could perturb structure; we don't claim adversarial robustness. Mitigations: augmentation, multi-depth ensembles, randomised bucketing, and planned adversarial training. Transparency about evasion cost is the point of the lab.

**12. Does it run offline?**
Yes: no outbound network at runtime; models and references ship as a versioned bundle; `docker compose up`.

**13. Is it safe to run on malware?**
Samples are never executed. Parsing happens in an ephemeral no-network, read-only, resource-limited container; only derived JSON crosses into the trusted pipeline. We assume parsers can be exploited and isolate accordingly.

**14. Is the evasion lab making malware harder to catch?**
It transforms benign programs from source with standard compilers/obfuscators to measure detector robustness. No new evasion method, no malware modification.

**15. What's the latency?**
Target p50 ≤ 30 s, p95 ≤ 90 s for ≤ 5 MB on a 4-core CPU; disassembly dominates; results are cached by SHA-256 + model version. Measured numbers in the benchmark tab.

**16. How does it handle unknown families?**
Open-set rule: if no family is close and no benign match is strong, verdict `suspicious/unknown` with the obfuscation panel. Leave-one-family-out quantifies this.

**17. Why Weisfeiler–Lehman?**
It's a principled graph-isomorphism-based kernel (Shervashidze et al., 2011): linear time, label-aware, captures local neighbourhood structure at chosen depth, requires no training, and yields interpretable features.

**18. Why a GNN as well?**
It learns which structural patterns matter beyond exact label matches, generalises across near-variants, and gives an independent score; disagreement with WL is surfaced as reduced confidence.

**19. What does this add over BinDiff/Diaphora or fuzzy hashes?**
Those are pairwise or byte-level tools for analysts. We provide a classifier + triage UI with explanations and measured robustness; we also benchmark against TLSH/ssdeep.

**20. What would you do with another month?**
Adversarial training, more families and architectures (ARM/MIPS for IoT), managed-code support, analyst feedback loop, SIEM/SOAR/STIX integration, safe automated unpacking research.

**21. Team/skills/credits?**
Mayank Sharma — AI/ML and cybersecurity builder. Cite: Weisfeiler–Lehman graph kernels (Shervashidze et al., JMLR 2011); GIN (Xu et al., ICLR 2019); call-graph malware work (Hu et al., CCS 2009; Kinable & Kostakis, 2011); Gemini (Xu et al., CCS 2017); EMBER (Anderson & Roth, 2018); MalConv (Raff et al., 2017); BODMAS (Yang et al., 2021); TESSERACT (Pendlebury et al., USENIX Security 2019). *(Verify citations before printing.)*

**22. "Reads the thoughts" — isn't that overclaiming?**
It's a tagline for *intent-level structure* versus surface bytes. Technically: we model what functions do (instruction/API semantics) and how they connect. The deck shows the measured limits.
