#!/usr/bin/env python3
"""Benchmark: Multi-turn Intent Classifier (TurnGate) via Ollama.

评测多轮对话意图识别模型的准确率和延迟，通过 Ollama 服务调用 GGUF 模型，
使用 logprobs + softmax 方式获取分类概率。

Usage (从 agent-sec-core/ 目录运行):
    # 默认评测 (每类 30 样本)
    uv run --project agent-sec-cli python3 \
        benchmarks/prompt-scan/scripts/bench_multi_turn_intent.py

    # 指定样本数
    uv run --project agent-sec-cli python3 \
        benchmarks/prompt-scan/scripts/bench_multi_turn_intent.py --n-samples 50

    # 自定义 Ollama 配置
    AGENT_SEC_OLLAMA_MODEL=turngate \
    AGENT_SEC_OLLAMA_BASE_URL=http://localhost:11434 \
    uv run --project agent-sec-cli python3 \
        benchmarks/prompt-scan/scripts/bench_multi_turn_intent.py

环境变量:
    AGENT_SEC_OLLAMA_BASE_URL   Ollama 服务地址 (default: http://localhost:11434)
    AGENT_SEC_OLLAMA_MODEL      模型名称 (default: turngate)
    AGENT_SEC_OLLAMA_TIMEOUT_SECONDS  超时时间 (default: 30)
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

# ── 路径设置 ──────────────────────────────────────────────────────────
_SCRIPT_DIR = Path(__file__).resolve().parent
_BENCHMARK_ROOT = _SCRIPT_DIR.parent
_DATASET_DIR = _BENCHMARK_ROOT / "datasets"
_CLI_ROOT = _BENCHMARK_ROOT.parent.parent / "agent-sec-cli"

# 让 import 能找到 agent_sec_cli
sys.path.insert(0, str(_CLI_ROOT / "src"))


def _load_samples(path: Path, limit: int) -> list[dict]:
    """Load test samples from JSONL and split into (history, query, response) triples."""
    triples: list[dict] = []
    seen: set = set()
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            idx = obj.get("sample_index")
            if idx in seen:
                continue
            seen.add(idx)

            conv = obj.get("conversation") or []
            target_turn = obj.get("target_turn")

            user_idx = None
            if target_turn is not None:
                for i, turn in enumerate(conv):
                    if turn.get("turn_id") == target_turn and turn.get("role") == "user":
                        user_idx = i
                        break
            if user_idx is None:
                for i in range(len(conv) - 2, -1, -1):
                    if conv[i].get("role") == "user" and conv[i + 1].get("role") == "assistant":
                        user_idx = i
                        break
            if user_idx is None:
                continue

            history = [
                {"role": t["role"], "content": t.get("content", "")}
                for t in conv[:user_idx]
            ]
            query = conv[user_idx].get("content", "")
            response = conv[user_idx + 1].get("content", "") if user_idx + 1 < len(conv) else ""
            if not query or not response:
                continue

            triples.append({"history": history, "query": query, "response": response})
            if len(triples) >= limit:
                break
    return triples


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-turn Intent Classifier Benchmark (Ollama)"
    )
    parser.add_argument(
        "--n-samples", type=int, default=30,
        help="每类 (harmful/benign) 取样数量 (default: 30)",
    )
    parser.add_argument(
        "--dataset-dir", type=str, default=None,
        help="数据集目录 (default: ../datasets/)",
    )
    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir) if args.dataset_dir else _DATASET_DIR
    harmful_path = dataset_dir / "harmful_test.jsonl"
    benign_path = dataset_dir / "benign_test.jsonl"

    for p in (harmful_path, benign_path):
        if not p.exists():
            print(f"ERROR: 数据集不存在: {p}")
            sys.exit(1)

    # ── Header ────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("  Multi-turn Intent Classifier Benchmark")
    print("  (TurnGate model via Ollama logprobs + softmax)")
    print(f"{'='*70}")
    print(f"  数据集目录: {dataset_dir}")
    print(f"  每类样本数: {args.n_samples}")

    # ── 1. 连接 Ollama ────────────────────────────────────────────────
    from agent_sec_cli.prompt_scanner.models.multi_intent import MultiIntentClassifier

    print("\n[1/3] 连接 Ollama...")
    t0 = time.perf_counter()
    classifier = MultiIntentClassifier()
    classifier.warmup()
    t_warmup = time.perf_counter() - t0
    print(f"      模型: {classifier.model_name}")
    print(f"      warmup 耗时: {t_warmup:.2f}s")

    # ── 2. 加载数据集 ─────────────────────────────────────────────────
    print("\n[2/3] 加载数据集...")
    harmful_triples = _load_samples(harmful_path, args.n_samples)
    benign_triples = _load_samples(benign_path, args.n_samples)
    print(f"      harmful: {len(harmful_triples)} samples")
    print(f"      benign:  {len(benign_triples)} samples")

    # ── 3. 推理评测 ──────────────────────────────────────────────────
    print(f"\n[3/3] 推理评测...")
    print("-" * 70)

    tp, fn = 0, 0
    harmful_latencies: list[float] = []
    for i, triple in enumerate(harmful_triples):
        result = classifier.classify(triple["history"], triple["query"], triple["response"])
        verdict, p_harm, lat = result["verdict"], result["p_harmful"], result["latency_ms"]
        harmful_latencies.append(lat)
        mark = "\u2713" if verdict == "block" else "\u2717"
        if verdict == "block":
            tp += 1
        else:
            fn += 1
        if i < 5 or verdict != "block":
            print(f"  harmful[{i:>2}] {mark} p_harmful={p_harm:.3f} lat={lat:.0f}ms")

    fp, tn = 0, 0
    benign_latencies: list[float] = []
    for i, triple in enumerate(benign_triples):
        result = classifier.classify(triple["history"], triple["query"], triple["response"])
        verdict, p_harm, lat = result["verdict"], result["p_harmful"], result["latency_ms"]
        benign_latencies.append(lat)
        mark = "\u2713" if verdict == "pass" else "\u2717"
        if verdict == "pass":
            tn += 1
        else:
            fp += 1
        if i < 5 or verdict != "pass":
            print(f"  benign[{i:>2}] {mark} p_harmful={p_harm:.3f} lat={lat:.0f}ms")

    # ── 汇总 ─────────────────────────────────────────────────────────
    n_harmful = len(harmful_triples)
    n_benign = len(benign_triples)
    tpr = tp / n_harmful if n_harmful else 0
    fpr = fp / n_benign if n_benign else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tpr
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    all_latencies = harmful_latencies + benign_latencies
    avg_lat = statistics.mean(all_latencies)
    med_lat = statistics.median(all_latencies)

    print(f"\n{'='*70}")
    print("  评测结果")
    print(f"{'='*70}")
    print(f"  Ollama 模型:       {classifier.model_name}")
    print(f"  分类阈值:         p_harmful > 0.50 → block")
    print(f"  Harmful 样本:     {n_harmful} (TP={tp}, FN={fn})")
    print(f"  Benign 样本:      {n_benign} (TN={tn}, FP={fp})")
    print(f"  TPR (Recall):     {tpr:.1%}")
    print(f"  FPR:              {fpr:.1%}")
    print(f"  Precision:        {precision:.1%}")
    print(f"  F1:               {f1:.3f}")
    print(f"  延迟 (ms):        avg={avg_lat:.0f}  med={med_lat:.0f}  min={min(all_latencies):.0f}  max={max(all_latencies):.0f}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
