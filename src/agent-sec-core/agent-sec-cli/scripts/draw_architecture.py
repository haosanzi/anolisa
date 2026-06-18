#!/usr/bin/env python3
"""Generate Prompt Scanner architecture diagram as PNG."""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np


def draw():
    fig, ax = plt.subplots(1, 1, figsize=(16, 10), dpi=150)
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 10)
    ax.axis("off")
    fig.patch.set_facecolor("#f8f9fa")

    # Colors
    C_HEADER = "#1a1a2e"
    C_L1 = "#e8f5e9"
    C_L1_BORDER = "#43a047"
    C_L2 = "#e3f2fd"
    C_L2_BORDER = "#1e88e5"
    C_L3 = "#f3e5f5"
    C_L3_BORDER = "#8e24aa"
    C_L4 = "#fff3e0"
    C_L4_BORDER = "#ef6c00"
    C_HOOK = "#fce4ec"
    C_HOOK_BORDER = "#c62828"
    C_MODE = "#eceff1"
    C_MODE_BORDER = "#546e7a"

    # Title
    ax.text(8, 9.5, "Prompt Scanner Architecture", ha="center", va="center",
            fontsize=20, fontweight="bold", color=C_HEADER,
            fontfamily="sans-serif")
    ax.text(8, 9.1, "agent-sec-cli  ·  Multi-Layer Defense Pipeline", ha="center",
            va="center", fontsize=11, color="#555", fontfamily="sans-serif")

    # --- Input arrows ---
    # UserPromptSubmit hook
    hook1 = FancyBboxPatch((0.3, 7.5), 3.2, 0.9, boxstyle="round,pad=0.12",
                            facecolor=C_HOOK, edgecolor=C_HOOK_BORDER, linewidth=1.5)
    ax.add_patch(hook1)
    ax.text(1.9, 8.1, "UserPromptSubmit", ha="center", va="center",
            fontsize=9, fontweight="bold", color=C_HOOK_BORDER)
    ax.text(1.9, 7.75, "cosh hook · single-turn", ha="center", va="center",
            fontsize=7.5, color="#666")

    # AfterModel hook
    hook2 = FancyBboxPatch((0.3, 6.2), 3.2, 0.9, boxstyle="round,pad=0.12",
                            facecolor=C_HOOK, edgecolor=C_HOOK_BORDER, linewidth=1.5)
    ax.add_patch(hook2)
    ax.text(1.9, 6.85, "AfterModel", ha="center", va="center",
            fontsize=9, fontweight="bold", color=C_HOOK_BORDER)
    ax.text(1.9, 6.5, "cosh hook · multi-turn triple", ha="center", va="center",
            fontsize=7.5, color="#666")

    # Arrows from hooks to scanner
    ax.annotate("", xy=(4.5, 7.4), xytext=(3.5, 7.7),
                arrowprops=dict(arrowstyle="-|>", color="#888", lw=1.5))
    ax.annotate("", xy=(4.5, 7.0), xytext=(3.5, 6.8),
                arrowprops=dict(arrowstyle="-|>", color="#888", lw=1.5))

    # --- Scanner core box ---
    scanner_box = FancyBboxPatch((4.5, 1.5), 7.5, 6.8, boxstyle="round,pad=0.2",
                                  facecolor="white", edgecolor="#333", linewidth=2)
    ax.add_patch(scanner_box)
    ax.text(8.25, 8.0, "PromptScanner", ha="center", va="center",
            fontsize=13, fontweight="bold", color=C_HEADER)
    ax.text(8.25, 7.6, "Preprocessor → Detect → Verdict", ha="center", va="center",
            fontsize=8.5, color="#777", style="italic")

    # --- L1 ---
    l1_box = FancyBboxPatch((5.0, 6.3), 6.5, 1.1, boxstyle="round,pad=0.1",
                             facecolor=C_L1, edgecolor=C_L1_BORDER, linewidth=2)
    ax.add_patch(l1_box)
    ax.text(5.3, 7.1, "L1", ha="left", va="center",
            fontsize=12, fontweight="bold", color=C_L1_BORDER)
    ax.text(6.1, 7.1, "Rule Engine", ha="left", va="center",
            fontsize=11, fontweight="bold", color="#333")
    ax.text(6.1, 6.7, "Regex / keyword patterns · injection + jailbreak rules", ha="left",
            va="center", fontsize=8, color="#555")
    ax.text(10.8, 7.1, "< 5ms", ha="right", va="center",
            fontsize=8.5, fontweight="bold", color=C_L1_BORDER,
            bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor=C_L1_BORDER, alpha=0.8))

    # --- L2 ---
    l2_box = FancyBboxPatch((5.0, 4.9), 6.5, 1.1, boxstyle="round,pad=0.1",
                             facecolor=C_L2, edgecolor=C_L2_BORDER, linewidth=2)
    ax.add_patch(l2_box)
    ax.text(5.3, 5.7, "L2", ha="left", va="center",
            fontsize=12, fontweight="bold", color=C_L2_BORDER)
    ax.text(6.1, 5.7, "ML Classifier", ha="left", va="center",
            fontsize=11, fontweight="bold", color="#333")
    ax.text(6.1, 5.3, "Llama Prompt Guard 2 (DeBERTa-v2, 86M) · binary classification",
            ha="left", va="center", fontsize=8, color="#555")
    ax.text(10.8, 5.7, "20-80ms", ha="right", va="center",
            fontsize=8.5, fontweight="bold", color=C_L2_BORDER,
            bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor=C_L2_BORDER, alpha=0.8))

    # --- L3 ---
    l3_box = FancyBboxPatch((5.0, 3.5), 6.5, 1.1, boxstyle="round,pad=0.1",
                             facecolor=C_L3, edgecolor=C_L3_BORDER, linewidth=2, linestyle="--")
    ax.add_patch(l3_box)
    ax.text(5.3, 4.3, "L3", ha="left", va="center",
            fontsize=12, fontweight="bold", color=C_L3_BORDER, alpha=0.6)
    ax.text(6.1, 4.3, "Semantic Detector", ha="left", va="center",
            fontsize=11, fontweight="bold", color="#999")
    ax.text(6.1, 3.9, "Vector similarity vs known attack patterns (planned, not implemented)",
            ha="left", va="center", fontsize=8, color="#999")
    ax.text(10.8, 4.3, "planned", ha="right", va="center",
            fontsize=8.5, fontweight="bold", color=C_L3_BORDER, alpha=0.6,
            bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor=C_L3_BORDER, alpha=0.4))

    # --- L4 ---
    l4_box = FancyBboxPatch((5.0, 2.1), 6.5, 1.1, boxstyle="round,pad=0.1",
                             facecolor=C_L4, edgecolor=C_L4_BORDER, linewidth=2)
    ax.add_patch(l4_box)
    ax.text(5.3, 2.9, "L4", ha="left", va="center",
            fontsize=12, fontweight="bold", color=C_L4_BORDER)
    ax.text(6.1, 2.9, "Multi-Turn Intent (TurnGate)", ha="left", va="center",
            fontsize=11, fontweight="bold", color="#333")
    ax.text(6.1, 2.5, "Qwen3-4B + RL fine-tuned · logit threshold 0.55 · sidecar server",
            ha="left", va="center", fontsize=8, color="#555")
    ax.text(10.8, 2.9, "~600ms", ha="right", va="center",
            fontsize=8.5, fontweight="bold", color=C_L4_BORDER,
            bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor=C_L4_BORDER, alpha=0.8))

    # Arrows between layers
    for y in [6.3, 4.9, 3.5]:
        ax.annotate("", xy=(8.25, y), xytext=(8.25, y + 0.05),
                    arrowprops=dict(arrowstyle="-|>", color="#bbb", lw=1.2))

    # --- Output arrow ---
    ax.annotate("", xy=(13.2, 4.5), xytext=(12.0, 4.5),
                arrowprops=dict(arrowstyle="-|>", color="#333", lw=2))

    # Verdict box
    verdict_box = FancyBboxPatch((13.2, 3.7), 2.3, 1.6, boxstyle="round,pad=0.15",
                                  facecolor="#e8eaf6", edgecolor="#283593", linewidth=2)
    ax.add_patch(verdict_box)
    ax.text(14.35, 4.9, "ScanResult", ha="center", va="center",
            fontsize=10, fontweight="bold", color="#283593")
    ax.text(14.35, 4.5, "verdict:", ha="center", va="center",
            fontsize=8.5, color="#555")
    ax.text(14.35, 4.1, "pass / warn / deny", ha="center", va="center",
            fontsize=9, fontweight="bold", color="#283593")

    # --- Mode legend ---
    mode_y = 0.6
    ax.text(0.5, mode_y + 0.4, "ScanMode Presets:", fontsize=9, fontweight="bold", color="#333")

    modes = [
        ("FAST", "L1 only", C_L1_BORDER),
        ("STANDARD", "L1 + L2", C_L2_BORDER),
        ("STRICT", "L1 + L2 + L3 (future)", C_L3_BORDER),
        ("INTENT_CHAIN", "L4 only (multi-turn)", C_L4_BORDER),
    ]
    for i, (name, desc, color) in enumerate(modes):
        x = 0.5 + i * 3.8
        mode_box = FancyBboxPatch((x, mode_y - 0.15), 3.4, 0.5, boxstyle="round,pad=0.08",
                                   facecolor=C_MODE, edgecolor=color, linewidth=1.5)
        ax.add_patch(mode_box)
        ax.text(x + 0.15, mode_y + 0.18, name, fontsize=8.5, fontweight="bold", color=color)
        ax.text(x + 0.15, mode_y - 0.05, desc, fontsize=7.5, color="#666")

    out_path = "/Users/yanrong/Desktop/anolisa/src/agent-sec-core/agent-sec-cli/docs/prompt_scanner_architecture.png"
    import os
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Saved to {out_path}")


if __name__ == "__main__":
    draw()
