#!/usr/bin/env python3
"""PromptScanner system architecture diagram — clean, high-level.

    .venv/bin/python scripts/draw_l4_architecture.py
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

matplotlib.rcParams["font.sans-serif"] = ["Arial Unicode MS", "Hiragino Sans GB", "STHeiti", "DejaVu Sans"]
matplotlib.rcParams["font.monospace"] = ["Menlo", "Monaco", "Arial Unicode MS", "DejaVu Sans Mono"]
matplotlib.rcParams["font.family"] = "sans-serif"
matplotlib.rcParams["axes.unicode_minus"] = False

BG = "#f9fafb"
DARK = "#1a1a2e"
WHITE = "#ffffff"


def box(ax, x, y, w, h, fc, ec, lw=2.0, ls="-", z=3):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1",
                                facecolor=fc, edgecolor=ec, linewidth=lw,
                                linestyle=ls, zorder=z))


def txt(ax, x, y, s, size=12, color="#333", bold=False, mono=False, z=10, ha="center", va="center"):
    ax.text(x, y, s, ha=ha, va=va, fontsize=size, color=color, zorder=z,
            fontweight="bold" if bold else "normal",
            fontfamily="monospace" if mono else "sans-serif")


def arr(ax, x1, y1, x2, y2, color="#555", lw=2.2, ls="-"):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", color=color, lw=lw,
                                linestyle=ls, shrinkA=5, shrinkB=5,
                                mutation_scale=22), zorder=8)


def draw():
    fig, ax = plt.subplots(1, 1, figsize=(20, 12), dpi=150)
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 12)
    ax.axis("off")
    fig.patch.set_facecolor(BG)

    # Title
    txt(ax, 10, 11.4, "PromptScanner 系统架构", size=26, color=DARK, bold=True)
    txt(ax, 10, 10.8, "AgentSecCore  ·  多层防御 + L4 多轮意图识别 + Code Agent Hook 集成",
        size=13, color="#607d8b")

    # ==================================================================
    # LEFT — Code Agent
    # ==================================================================
    box(ax, 0.4, 1.5, 4.6, 8.5, "#e8f5e9", "#2e7d32", lw=2.5, z=1)
    txt(ax, 2.7, 9.6, "Code Agent", size=16, color="#2e7d32", bold=True)

    # cosh
    box(ax, 0.8, 7.8, 3.8, 1.5, WHITE, "#388e3c", lw=1.8, z=3)
    txt(ax, 2.7, 8.85, "cosh", size=14, color="#2e7d32", bold=True)
    txt(ax, 2.7, 8.3, "Claude Code 扩展", size=11, color="#555")
    txt(ax, 2.7, 7.95, "cosh-extension.json", size=10, color="#777", mono=True)

    # openclaw
    box(ax, 0.8, 5.9, 3.8, 1.5, WHITE, "#388e3c", lw=1.8, z=3)
    txt(ax, 2.7, 6.95, "openclaw", size=14, color="#2e7d32", bold=True)
    txt(ax, 2.7, 6.4, "Code Agent 插件", size=11, color="#555")
    txt(ax, 2.7, 6.05, "openclaw.plugin.json", size=10, color="#777", mono=True)

    # Hooks
    box(ax, 0.8, 2.0, 3.8, 3.5, "#fff3e0", "#ef6c00", lw=2.2, z=3)
    txt(ax, 2.7, 5.05, "Hook 集成层", size=13, color="#ef6c00", bold=True)
    txt(ax, 2.7, 4.4, "UserPromptSubmit", size=11.5, color="#333", bold=True)
    txt(ax, 2.7, 3.9, "→ 触发 L1 / L2 / L3 扫描", size=10.5, color="#555")
    txt(ax, 2.7, 3.2, "AfterModel", size=11.5, color="#e65100", bold=True)
    txt(ax, 2.7, 2.7, "→ 触发 L4 多轮意图检测", size=10.5, color="#555")
    txt(ax, 2.7, 2.2, "fail-open · 异常不阻断会话", size=9.5, color="#888")

    # Agent internal arrow
    arr(ax, 2.7, 7.8, 2.7, 5.52, "#9e9e9e", 1.6)

    # ==================================================================
    # CENTER — PromptScanner
    # ==================================================================
    box(ax, 5.8, 1.5, 7.0, 8.5, "#fafafa", "#37474f", lw=2.8, z=1)
    txt(ax, 9.3, 9.6, "PromptScanner", size=16, color="#37474f", bold=True)
    txt(ax, 9.3, 9.0, "agent-sec-cli · security_middleware", size=11, color="#78909c")

    # L1
    box(ax, 6.2, 7.5, 6.2, 1.2, "#e8f5e9", "#43a047", lw=2.0, z=3)
    txt(ax, 6.7, 8.1, "L1", size=13, color="#43a047", bold=True, ha="left")
    txt(ax, 8.0, 8.1, "Rule Engine", size=12, color="#333", bold=True, ha="left")
    txt(ax, 8.0, 7.7, "正则 / 关键词匹配", size=10.5, color="#555", ha="left")
    txt(ax, 12.0, 8.1, "< 5ms", size=10, color="#43a047", bold=True, ha="right")

    # L2
    box(ax, 6.2, 5.9, 6.2, 1.2, "#e3f2fd", "#1e88e5", lw=2.0, z=3)
    txt(ax, 6.7, 6.5, "L2", size=13, color="#1e88e5", bold=True, ha="left")
    txt(ax, 8.0, 6.5, "ML Classifier", size=12, color="#333", bold=True, ha="left")
    txt(ax, 8.0, 6.1, "Prompt-Guard-2 (86M)", size=10.5, color="#555", ha="left")
    txt(ax, 12.0, 6.5, "20-80ms", size=10, color="#1e88e5", bold=True, ha="right")

    # L3
    box(ax, 6.2, 4.3, 6.2, 1.2, "#f3e5f5", "#8e24aa", lw=1.6, ls="--", z=3)
    txt(ax, 6.7, 4.9, "L3", size=13, color="#8e24aa", bold=True, ha="left")
    txt(ax, 8.0, 4.9, "Semantic", size=12, color="#999", bold=True, ha="left")
    txt(ax, 8.0, 4.5, "向量语义检索（规划中）", size=10.5, color="#999", ha="left")
    txt(ax, 12.0, 4.9, "—", size=10, color="#999", ha="right")

    # L4 — highlight
    box(ax, 6.2, 2.7, 6.2, 1.2, "#fff3e0", "#ef6c00", lw=3.0, z=3)
    txt(ax, 6.7, 3.3, "L4", size=14, color="#ef6c00", bold=True, ha="left")
    txt(ax, 8.0, 3.3, "Multi-Turn Intent", size=12.5, color="#333", bold=True, ha="left")
    txt(ax, 8.0, 2.9, "TurnGate · Qwen3-4B", size=10.5, color="#555", ha="left")
    txt(ax, 12.0, 3.3, "~600ms", size=10, color="#ef6c00", bold=True, ha="right")

    # ScanResult
    box(ax, 6.8, 1.7, 5.0, 0.75, "#e8eaf6", "#283593", lw=2.0, z=3)
    txt(ax, 9.3, 2.08, "ScanResult → pass / warn / deny", size=11.5, color="#283593", bold=True)

    # Layer flow arrow
    arr(ax, 9.3, 2.7, 9.3, 2.47, "#bdbdbd", 1.5)

    # ==================================================================
    # RIGHT — L4 Sidecar
    # ==================================================================
    box(ax, 13.6, 1.5, 6.0, 8.5, "#fff8e1", "#e65100", lw=2.8, z=1)
    txt(ax, 16.6, 9.6, "L4 intent-server", size=15, color="#e65100", bold=True)
    txt(ax, 16.6, 9.0, "独立 sidecar 进程 · 每机一实例", size=11, color="#8a6d00")

    # HTTP
    box(ax, 14.0, 7.3, 5.2, 1.6, WHITE, "#e65100", lw=1.8, z=3)
    txt(ax, 16.6, 8.45, "HTTP Server", size=13, color="#e65100", bold=True)
    txt(ax, 16.6, 7.9, "localhost 回环通信", size=11, color="#555")
    txt(ax, 16.6, 7.5, "/classify  ·  /health", size=10.5, color="#777", mono=True)

    # Model
    box(ax, 14.0, 4.5, 5.2, 2.4, "#ffe0b2", "#bf360c", lw=2.2, z=3)
    txt(ax, 16.6, 6.45, "TurnGate Qwen3-4B", size=13, color="#bf360c", bold=True)
    txt(ax, 16.6, 5.9, "自训练端侧模型（RL 微调）", size=11, color="#6d4c00")
    txt(ax, 16.6, 5.35, "logit 判定  p_harmful > 0.55", size=10.5, color="#555")
    txt(ax, 16.6, 4.8, "cpu / cuda / mps 自适应", size=10, color="#888")

    # Lifecycle
    box(ax, 14.0, 2.0, 5.2, 2.1, WHITE, "#9e8a6b", lw=1.5, ls="--", z=3)
    txt(ax, 16.6, 3.7, "生命周期管理", size=12, color="#6d5a3a", bold=True)
    txt(ax, 16.6, 3.15, "懒启动 · idle 30min 自动退出", size=10.5, color="#666")
    txt(ax, 16.6, 2.6, "PID / PORT 文件协调", size=10.5, color="#666")

    # Internal arrow
    arr(ax, 16.6, 7.3, 16.6, 6.92, "#bbb", 1.5)

    # ==================================================================
    # Connecting arrows
    # ==================================================================
    # Hook -> PromptScanner
    arr(ax, 4.6, 4.0, 5.8, 5.5, "#ef6c00", 2.6)
    txt(ax, 5.2, 5.2, "stdin", size=10, color="#ef6c00", bold=True)

    # L4 layer -> Sidecar
    arr(ax, 12.4, 3.3, 14.0, 7.8, "#ef6c00", 2.6)
    txt(ax, 13.6, 6.0, "POST\n/classify", size=10, color="#ef6c00", bold=True)

    # Sidecar -> L4 verdict (return)
    arr(ax, 14.0, 5.5, 12.4, 3.0, "#2e7d32", 2.2, ls=(0, (5, 3)))
    txt(ax, 13.5, 3.8, "verdict", size=10, color="#2e7d32", bold=True)

    # Result -> Agent
    arr(ax, 5.8, 2.08, 4.6, 3.0, "#2e7d32", 2.2, ls=(0, (5, 3)))
    txt(ax, 4.7, 2.2, "decision", size=10, color="#2e7d32", bold=True)

    # ==================================================================
    # Legend
    # ==================================================================
    txt(ax, 14.2, 1.0, "图例:", size=11, color="#333", bold=True, ha="left")
    ax.annotate("", xy=(15.4, 1.0), xytext=(14.8, 1.0),
                arrowprops=dict(arrowstyle="-|>", color="#ef6c00", lw=2.2), zorder=8)
    txt(ax, 15.6, 1.0, "请求流", size=10, color="#555", ha="left")
    ax.annotate("", xy=(17.5, 1.0), xytext=(16.9, 1.0),
                arrowprops=dict(arrowstyle="-|>", color="#2e7d32", lw=2.2,
                                linestyle=(0, (5, 3))), zorder=8)
    txt(ax, 17.7, 1.0, "结果回传", size=10, color="#555", ha="left")

    # Save
    out_dir = "/Users/yanrong/Desktop/anolisa/src/agent-sec-core/agent-sec-cli/docs"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "l4_multi_turn_intent_architecture.png")
    fig.savefig(out_path, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Saved to {out_path}")
    return out_path


if __name__ == "__main__":
    draw()
