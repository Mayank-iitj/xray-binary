# X-Ray Binary — Algorithms

Companion to `TRD.md`. Reference code: `reference/wl_kernel.py`, `reference/obfuscation.py`, `reference/extract_r2.py`.

## 1. Notation
- Call graph `G = (V, E)`, directed, `|V| = n`. Node `v` has structure-only label `ℓ0(v)` (TRD §3.3).
- `N⁺(v)` = callees, `N⁻(v)` = callers. `h` = WL depth (default 3).

## 2. Node label construction
For function `v` with instruction list `I_v`:
1. Map each instruction to a coarse class `c(i)` (data, stack, arith, logic, xor, shift, cmp, jmp, cjmp, call, ret, nop, mem, other).
2. Profile `p_v[c] = |{i : c(i)=c}| / |I_v|`, bucketed to deciles.
3. API bucket set `A_v` from imports called by `v` (normalised names → semantic buckets).
4. CFG stats: cyclomatic complexity `cc = E_cfg − N_cfg + 2`, `bb = ⌊#blocks/4⌋` (capped).
5. `ℓ0(v) = "profile | api:A_v | cc:min(cc,20) | bb:min(bb,10)"`; hashed with BLAKE2b-64.

Invariance argument: none of the inputs depend on bytes, names, strings or addresses. Renaming, string encryption and relocation do not change `ℓ0`. Junk code and recompilation *do* perturb profiles; this is measured, not assumed (EVASION_LAB.md).

Design trade-off: decile bucketing makes labels discrete (needed for hashing) but makes profiles near a bucket boundary flip under small perturbations. Mitigations to ablate: (a) coarser buckets (quartiles), (b) dropping the profile from the label at depth 0 and relying on API+CFG, (c) k-means profile cluster IDs instead of deciles, (d) augmentation of the GNN with multi-compiler variants.

## 3. Weisfeiler-Lehman fingerprint (directed 1-WL)
```
ℓ_{t+1}(v) = H( ℓ_t(v) ‖ sort{ℓ_t(u) : u ∈ N⁺(v)} ‖ sort{ℓ_t(u) : u ∈ N⁻(v)} )
φ(G) = histogram over { (t, ℓ_t(v)) : 0 ≤ t ≤ h, v ∈ V }
```
- Cost `O(h·(|V|+|E|))`, label collisions negligible with 64-bit hashes at these sizes (report collision probe in tests).
- Isomorphism-invariant by construction (property test: any node renaming yields identical `φ`).
- Directed neighbourhoods keep caller/callee distinction, which matters for "who calls crypto" vs "who is called by crypto".

## 4. Similarity and matching
Sublinear TF with IDF: `w(k) = (1 + ln c_k) · idf(k)`, `idf(k) = ln((1+N)/(1+df(k))) + 1`.
`sim(a,b) = Σ w_a(k) w_b(k) / (‖w_a‖ ‖w_b‖)` ∈ [0,1].

Per family `f` with reference set `R_f`:
- `s_f^max = max_{r∈R_f} sim(φ(G), φ(r))`
- `s_f^top3 = mean of top-3 sims`
Benign score `s_b` computed the same way against the benign set. IDF is fit on the *training* reference corpus only (never on test data).

Why IDF matters: CRT/startup and common compiler idioms appear in nearly every binary; IDF downweights them so family-specific structure dominates.

Library pruning (P1): remove nodes matched by library signatures or whose WL depth-2 label appears in > τ_lib of benign documents *and* has no API bucket; report pruned fraction in the report.

## 5. Discriminative node attribution
Document-frequency log-odds with additive smoothing `α=1` for label `k` (depth ≥ 1):
```
λ_f(k) = logit((df_f(k)+α)/(N_f+2α)) − logit((df_b(k)+α)/(N_b+2α))
score(v) = mean of the top-2 values of max(λ_f(k), 0) over v's labels at depths 1..h
```
Interpretation: a node is suspicious to the degree that its multi-hop structural context is common in the matched family and rare in benign software. Depth-0 labels are excluded (too generic).

Faithfulness check (EVALUATION_PLAN §6): ablate (zero out) the top-k% scored nodes' contributions, recompute `s_f`; a faithful attribution produces a larger drop than random-k% and than top-k% by degree.

Secondary view: GNN occlusion `Δ = logit_f(G) − logit_f(G∖v)`; report rank agreement (Spearman) between the two attributions. Disagreement is shown to the analyst, not hidden.

## 6. GNN scorer
- Input: node features `x_v` = [profile (14), API multi-hot (10), CFG stats (6), degrees/depth (5), size (1)], standardised on train.
- Model: 3× GIN layers (hidden 128, MLP 2-layer, BatchNorm, dropout 0.3) → readout `[sum ‖ max]` → MLP → logits over `{benign, ransomware, keylogger, downloader}` plus a 64-d embedding for kNN.
- Training: class-balanced cross-entropy, AdamW (lr 1e-3, wd 1e-4), early stopping on validation macro-F1, 5 seeds; report mean±std. Graph truncation: ≤ 5000 nodes (largest + all API-bearing).
- Augmentation: include multi-compiler/optimisation variants of benign build corpus and transformed (renamed/stripped) copies as extra benign and as extra family-surrogate training examples *only where labels are certain*.
- Inference deterministic (`eval()`, fixed seeds, deterministic algorithms flag).

## 7. Fusion, calibration, open set
Features `z = [s_f^max (all f), s_b, gnn_probs, packed_flag, cff_max, xor_loops>0, partial_flag]`.
- Stage 1: multinomial logistic regression → class probabilities.
- Stage 2: calibration on a held-out *calibration* split (Platt for binary malware prob, temperature scaling for family). Report ECE.
- Open set: `unknown` if `max_f s_f^max < τ_sim` and `max gnn prob < τ_p`; thresholds from validation to bound false "known family" rate. Verdict still `malicious/suspicious` if `p_mal ≥ T`.
- Thresholds `T_high` (≈0.5% FPR) and `T_low` (≈5% FPR) fixed on validation, versioned.

## 8. Obfuscation detectors (details of `reference/obfuscation.py`)
**CFF.** For function CFG `g`: dispatcher `d = argmax in_degree`. `back_ratio` = fraction of non-entry blocks whose only successor is `d`. `fan_ratio = in_deg(d)/|blocks|`. Require `out_deg(d) ≥ 3`. `score = 0.6·back_ratio + 0.4·min(1, 2·fan_ratio)`. Limitation: switch-heavy legitimate code (interpreters, state machines) scores high; the UI shows evidence and never auto-convicts on this alone.
**XOR decode.** Strongly connected component with: non-zeroing `xor` (operands differ), memory store, counter update, conditional branch. Excludes `xor reg,reg` idiom. Limitation: legitimate checksum/crypto loops match; hence context (what calls it, what it feeds) is shown.
**Packing.** Evidence list from section entropy (> 7.2 on executable section), W+X section, entry in high-entropy section; `packed_likely` if ≥ 2 pieces of evidence. Sparse-import and unpacker-API (`VirtualProtect`+`LoadLibrary`+`GetProcAddress` only) as extra evidence.
**Junk code.** Fraction of instructions in NOP-equivalent/dead-store patterns per function; flagged if ≫ benign distribution (percentile from benign corpus).
All detectors return `{score, evidence[]}`; scores are heuristics calibrated against the benign corpus (report FP rate per detector).

## 9. Retention metrics (Evasion Lab)
For original binary `o` and variant `x`:
- `R_cos = sim(φ(o), φ(x))` (IDF from reference corpus).
- `R_disc` = Jaccard of the top-K discriminative labels (K=200).
- `R_node` = fraction of `o`'s nodes with a structurally matching node in `x` (greedy match by depth-2 label then API set).
- `R_verdict` = 1 if the family verdict is unchanged, else 0 (aggregate as rate).
Baseline retention for signature-style matchers is computed on the same pair `(o,x)`: exact-hash match (0/1), TLSH/ssdeep similarity, byte 4-gram Jaccard, and match of a YARA rule auto-generated from `o` (0/1).
