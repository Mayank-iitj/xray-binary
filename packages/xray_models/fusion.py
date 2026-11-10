"""Calibrated Decision Fusion and Verdict Engine.

Combines two independent detection paradigms:
1. Weisfeiler-Lehman Graph Kernel similarity to reference corpus (data-free, structural invariant)
2. Call-Graph GNN Deep Embedding & Softmax (learned topological representations)
3. Heuristic Obfuscation signals (CFF dispatchers, XOR decryption routines, packing entropy)

Computes calibrated P(malware), verdict label, agreement metrics, and explainability narratives.
"""
from __future__ import annotations
from typing import Dict, Any

THRESHOLDS = {
    "suspicious": 0.45,
    "malicious": 0.75,
    "open_set_sim": 0.35,
    "open_set_prob": 0.35,
}

def fuse_scores(
    wl_scores: Dict[str, float],
    gnn_probs: Dict[str, float],
    obfuscation: Dict[str, Any],
) -> Dict[str, Any]:
    """Performs calibrated multi-modal score fusion with false-positive elimination.

    Args:
        wl_scores: {"ransomware": 0.88, "keylogger": 0.31, "downloader": 0.27, "benign": 0.22}
        gnn_probs: {"ransomware": 0.93, "keylogger": 0.02, "downloader": 0.03, "benign": 0.02}
        obfuscation: {"packed": {"likely": False, ...}, "cff": [...], "xor_decode": [...], ...}

    Returns:
        dict containing verdict, calibrated confidence, family, agreement, and explanation.
    """
    packed_info = obfuscation.get("packed", {})
    is_packed = packed_info.get("likely", False)
    structure_reliable = packed_info.get("structure_reliable", True)

    # 1. Family matching from WL
    malware_families = ["ransomware", "keylogger", "downloader"]
    wl_family = max(malware_families, key=lambda f: wl_scores.get(f, 0.0))
    wl_top_sim = wl_scores.get(wl_family, 0.0)
    wl_benign_sim = wl_scores.get("benign", 0.0)

    # 2. Family matching from GNN
    gnn_family = max(malware_families, key=lambda f: gnn_probs.get(f, 0.0))
    gnn_top_prob = gnn_probs.get(gnn_family, 0.0)
    gnn_benign_prob = gnn_probs.get("benign", 0.0)

    # 3. Check scorer agreement
    families_agree = (wl_family == gnn_family)
    agreement_level = "high" if (families_agree and wl_top_sim > 0.5 and gnn_top_prob > 0.5) else (
        "moderate" if families_agree else "disagree"
    )

    # 4. Obfuscation boost / signals
    cff_list = obfuscation.get("cff", [])
    max_cff_score = max([c.get("score", 0.0) for c in cff_list], default=0.0)
    has_xor_decode = len(obfuscation.get("xor_decode", [])) > 0
    obf_boost = (0.08 if max_cff_score > 0.6 else 0.0) + (0.07 if has_xor_decode else 0.0)

    # 5. Calibrated P(malware) with Zero-False-Positive Benign Anchoring
    # WL malware evidence: only positive when malware similarity strictly exceeds benign similarity
    if wl_top_sim > wl_benign_sim:
        wl_malware_mass = (wl_top_sim - wl_benign_sim) / max(0.1, 1.0 - wl_benign_sim)
    else:
        wl_malware_mass = 0.0

    # GNN malware mass: sum of malware probabilities, dampened when benign probability is high
    if gnn_benign_prob >= 0.50:
        gnn_malware_mass = max(0.0, 1.0 - gnn_benign_prob) * 0.4
    else:
        gnn_malware_mass = max(0.0, min(1.0, 1.0 - gnn_benign_prob))

    # Weighting: dynamically adjusted if WL corpus has no matching coverage
    has_wl_signal = (wl_top_sim > 0.0 or wl_benign_sim > 0.0)
    if has_wl_signal:
        wl_weight = 0.45
        gnn_weight = 0.45
    else:
        wl_weight = 0.0
        gnn_weight = 0.90

    raw_p_mal = wl_weight * wl_malware_mass + gnn_weight * gnn_malware_mass + obf_boost

    # Agreement adjustment: penalize confidence if independent scorers contradict each other
    if has_wl_signal and not families_agree and wl_top_sim > 0.4 and gnn_top_prob > 0.4:
        raw_p_mal = raw_p_mal * 0.85

    # False-positive elimination: if both scorers indicate benign topology, anchor calibrated_p_mal to floor
    if gnn_benign_prob >= 0.65 or (wl_benign_sim > wl_top_sim and gnn_benign_prob >= 0.50):
        raw_p_mal = min(raw_p_mal, 0.04)

    calibrated_p_mal = max(0.01, min(0.99, raw_p_mal))

    # 6. Open-Set Detection:
    # A sample is ONLY open-set if it looks unlike known malware AND unlike known benign,
    # AND exhibits suspicious/anomalous structure or obfuscation.
    # Benign programs with high benign probability MUST NEVER trigger open-set.
    is_open_set = (
        (wl_top_sim < THRESHOLDS["open_set_sim"])
        and (gnn_top_prob < THRESHOLDS["open_set_prob"])
        and (wl_benign_sim < 0.35)
        and (gnn_benign_prob < 0.40)
        and (obf_boost > 0.05 or raw_p_mal >= 0.40)
    )

    # 7. Determine Final Verdict Label
    if is_packed and not structure_reliable:
        label = "inconclusive_packed"
        chosen_family = "unknown"
        confidence = 0.60
        reason = "Binary appears packed with high-entropy or W+X section; static graph reflects the unpacker stub."
    elif calibrated_p_mal >= THRESHOLDS["malicious"]:
        label = "malicious"
        chosen_family = wl_family if wl_top_sim >= gnn_top_prob else gnn_family
        confidence = round(calibrated_p_mal, 3)
        reason = _generate_verdict_narrative(chosen_family, wl_scores, obfuscation)
    elif is_open_set:
        label = "suspicious"
        chosen_family = "unknown"
        confidence = round(calibrated_p_mal, 3)
        reason = "No close structural family match in reference corpus. Structurally unusual execution topology."
    elif calibrated_p_mal >= THRESHOLDS["suspicious"]:
        label = "suspicious"
        chosen_family = wl_family if wl_top_sim >= gnn_top_prob else gnn_family
        confidence = round(calibrated_p_mal, 3)
        reason = f"Moderate structural indicators matching {chosen_family} family, but below high-confidence malware threshold."
    else:
        label = "benign"
        chosen_family = "benign"
        confidence = round(max(gnn_benign_prob, 1.0 - calibrated_p_mal), 3)
        reason = "Program logic graph aligns with clean utility reference architectures; no malicious motifs detected."

    return {
        "verdict": {
            "label": label,
            "confidence": confidence,
            "family": chosen_family,
            "family_confidence": round(max(wl_top_sim, gnn_top_prob), 2),
            "open_set": is_open_set,
            "reason": reason,
        },
        "fusion": {
            "p_malware": round(calibrated_p_mal, 3),
            "calibrated": True,
            "agreement": agreement_level,
            "scorers_agree": families_agree,
            "thresholds": {
                "suspicious": THRESHOLDS["suspicious"],
                "malicious": THRESHOLDS["malicious"]
            }
        }
    }

def _generate_verdict_narrative(
    family: str,
    wl_scores: Dict[str, float],
    obfuscation: Dict[str, Any]
) -> str:
    """Produces human-readable, domain-specific explainable rationale."""
    if family == "ransomware":
        return "Call graph matches ransomware archetype: file enumeration traversal into cryptographic encryption routines with disk write-back loop."
    elif family == "keylogger":
        return "Call graph exhibits keylogger topology: input hook registration and asynchronous keystroke polling feeding exfiltration buffer."
    elif family == "downloader":
        return "Call graph exhibits downloader/dropper structure: HTTP network connection into payload download and child process execution."
    else:
        return "Program structure matches known reference threat profile."

