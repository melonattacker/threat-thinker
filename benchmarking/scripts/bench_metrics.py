#!/usr/bin/env python3
"""
Benchmark Metrics Driver for Threat Thinker
------------------------------------------
- Manual mode: compute precision/recall/F1 from counts.
- Benchmark mode (default): run `threat-thinker think` against prepared diagrams,
  compare results against detection rules in `expected_threats.json`, and report metrics.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from math import sqrt
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - optional dependency
    OpenAI = None

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_BENCH_ROOT = SCRIPT_DIR.parent
DEFAULT_REPO_ROOT = DEFAULT_BENCH_ROOT.parent
DEFAULT_REPORT_DIR = DEFAULT_REPO_ROOT / "reports" / "benchmarks"
DEFAULT_FIELDS = ["title", "why"]
DEFAULT_EMBEDDING_MODEL = "text-embedding-3-large"
Vector = Tuple[float, ...]


def safe_div(n: int, d: int) -> float:
    """Safely divide two numbers, returning 0.0 if denominator is zero."""
    return 0.0 if d == 0 else n / d


def compute_metrics(accepted: int, outputs: int, gold: int) -> Tuple[float, float, float]:
    precision = safe_div(accepted, outputs)
    recall = safe_div(accepted, gold)
    f1 = 0.0 if (precision + recall) == 0 else (2 * precision * recall) / (precision + recall)
    return precision, recall, f1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Benchmark precision/recall for `threat-thinker think` outputs."
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Use manual input mode (prompts for accepted/outputs/gold like previous script).",
    )

    manual = parser.add_argument_group("manual mode inputs")
    manual.add_argument("-a", "--accepted", type=int, help="Accepted (correct) threats.")
    manual.add_argument("-o", "--outputs", type=int, help="Total threats generated.")
    manual.add_argument("-g", "--gold", type=int, help="Ground-truth threats.")

    parser.add_argument("--llm-api", help="LLM provider passed to `threat-thinker think`.")
    parser.add_argument("--llm-model", help="LLM model passed to `threat-thinker think`.")
    parser.add_argument(
        "--benchmark-root",
        type=Path,
        default=DEFAULT_BENCH_ROOT,
        help="Root directory that contains scenario folders (default: %(default)s).",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help="Repository root used to resolve diagram/report paths (default: %(default)s).",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=DEFAULT_REPORT_DIR,
        help="Directory to store generated JSON reports (default: %(default)s).",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        help="Optional list of scenario folder names to evaluate (default: all).",
    )
    parser.add_argument(
        "--topn",
        type=int,
        default=10,
        help="Value passed to `--topn` when invoking `threat-thinker think` (default: 10).",
    )
    parser.add_argument(
        "--infer-hints",
        dest="infer_hints",
        action="store_true",
        help="Enable `--infer-hints` when calling the CLI (default).",
    )
    parser.add_argument(
        "--no-infer-hints",
        dest="infer_hints",
        action="store_false",
        help="Disable `--infer-hints` when calling the CLI.",
    )
    parser.set_defaults(infer_hints=True)
    parser.add_argument(
        "--decimals",
        type=int,
        default=4,
        help="Decimal precision for printed metrics (default: 4).",
    )
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.6,
        help=(
            "Minimum cosine similarity (0-1) across selected fields required to count a match "
            "(default: 0.6)."
        ),
    )
    parser.add_argument(
        "--embedding-model",
        default=DEFAULT_EMBEDDING_MODEL,
        help=(
            "OpenAI embedding model name used for semantic matching "
            "(default: %(default)s)."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Return metrics as JSON.")
    return parser


def gather_manual_inputs(args: argparse.Namespace) -> Tuple[int, int, int]:
    """Prompt for manual inputs if arguments were not supplied."""
    a, o, g = args.accepted, args.outputs, args.gold

    try:
        if a is None:
            a = int(input("Accepted (correct threats): ").strip())
        if o is None:
            o = int(input("Outputs (total threats generated): ").strip())
        if g is None:
            g = int(input("Gold (expected threats): ").strip())
    except Exception as exc:  # pragma: no cover - interactive prompt
        print(f"Input error: {exc}", file=sys.stderr)
        sys.exit(1)

    return a, o, g


def validate_counts(accepted: int, outputs: int, gold: int) -> None:
    if any(x < 0 for x in (accepted, outputs, gold)):
        print("Counts must be non-negative.", file=sys.stderr)
        sys.exit(2)
    if accepted > outputs:
        print("Accepted cannot exceed total outputs.", file=sys.stderr)
        sys.exit(3)
    if accepted > gold:
        print("Accepted cannot exceed gold (expected threats).", file=sys.stderr)
        sys.exit(4)


def manual_mode(args: argparse.Namespace) -> None:
    accepted, outputs, gold = gather_manual_inputs(args)
    validate_counts(accepted, outputs, gold)
    precision, recall, f1 = compute_metrics(accepted, outputs, gold)
    decimals = args.decimals

    payload = {
        "accepted": accepted,
        "outputs": outputs,
        "gold": gold,
        "precision": round(precision, decimals),
        "recall": round(recall, decimals),
        "f1": round(f1, decimals),
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
        return

    fmt = f"{{:.{decimals}f}}"
    print(f"Accepted : {accepted}")
    print(f"Outputs  : {outputs}")
    print(f"Gold     : {gold}")
    print(f"Precision: {fmt.format(precision)}")
    print(f"Recall   : {fmt.format(recall)}")
    print(f"F1 Score : {fmt.format(f1)}")


def discover_scenarios(benchmark_root: Path) -> List[Path]:
    candidates: List[Path] = []
    for child in benchmark_root.iterdir():
        if child.is_dir() and (child / "expected_threats.json").exists():
            candidates.append(child)
    candidates.sort()
    return candidates


def resolve_path(candidate: str, repo_root: Path) -> Path:
    path = Path(candidate)
    if not path.is_absolute():
        path = repo_root / path
    return path


def load_expected(path: Path) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def build_similarity_text(record: Dict[str, Any]) -> str:
    texts = [text for text in extract_field_text(record, DEFAULT_FIELDS)]
    return " ".join(texts).strip()


def cosine_similarity(left: Vector, right: Vector) -> float:
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = sqrt(sum(a * a for a in left))
    right_norm = sqrt(sum(b * b for b in right))
    denom = left_norm * right_norm
    if denom == 0:
        return 0.0
    return dot / denom


class SimilarityEngine:
    def __init__(self, model_name: str):
        if OpenAI is None:
            print("openai package is required for embedding matching.", file=sys.stderr)
            sys.exit(10)
        if not os.getenv("OPENAI_API_KEY"):
            print("OPENAI_API_KEY must be set to compute embedding similarities.", file=sys.stderr)
            sys.exit(11)
        self.client = OpenAI()
        self.model_name = model_name
        self._cache: Dict[Tuple[str, int], Optional[Vector]] = {}

    def _embed(self, text: str) -> Optional[Vector]:
        if not text:
            return None
        try:
            response = self.client.embeddings.create(model=self.model_name, input=[text])
        except Exception as exc:  # pragma: no cover - runtime env issues
            print(f"Failed to compute embeddings via OpenAI: {exc}", file=sys.stderr)
            sys.exit(12)
        embedding = response.data[0].embedding
        return tuple(float(value) for value in embedding)

    def _key(self, kind: str, index: int) -> Tuple[str, int]:
        return (kind, index)

    def embedding_for_expected(self, index: int, record: Dict[str, Any]) -> Optional[Vector]:
        key = self._key("expected", index)
        if key not in self._cache:
            text = build_similarity_text(record)
            self._cache[key] = self._embed(text)
        return self._cache[key]

    def embedding_for_threat(self, index: int, record: Dict[str, Any]) -> Optional[Vector]:
        key = self._key("threat", index)
        if key not in self._cache:
            text = build_similarity_text(record)
            self._cache[key] = self._embed(text)
        return self._cache[key]


def load_similarity_engine(model_name: str) -> SimilarityEngine:
    return SimilarityEngine(model_name)


def extract_field_text(threat: Dict[str, Any], fields: Sequence[str]) -> Iterable[str]:
    for field in fields:
        value = threat.get(field)
        if value is None:
            continue
        if isinstance(value, list):
            yield " ".join(str(item) for item in value)
        else:
            yield str(value)


def match_expected(
    expected_entry: Dict[str, Any],
    entry_index: int,
    actual_threats: Sequence[Dict[str, Any]],
    similarity_engine: SimilarityEngine,
    default_similarity_threshold: float,
) -> Optional[Dict[str, Any]]:
    detection = expected_entry.get("detection") or {}
    expected_embedding = similarity_engine.embedding_for_expected(entry_index, expected_entry)
    if expected_embedding is None:
        return None

    threshold = (
        detection.get("threshold")
        or detection.get("similarity_threshold")
        or default_similarity_threshold
    )

    best_match: Optional[Dict[str, Any]] = None
    best_score = threshold

    for idx, threat in enumerate(actual_threats):
        threat_embedding = similarity_engine.embedding_for_threat(idx, threat)
        if threat_embedding is None:
            continue
        score = cosine_similarity(expected_embedding, threat_embedding)
        if score >= best_score:
            best_match = threat
            best_score = score
    return best_match


def run_threat_thinker(
    diagram_path: Path,
    report_path: Path,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    cmd = [
        "threat-thinker",
        "think",
        "--mermaid",
        str(diagram_path),
        "--topn",
        str(args.topn),
        "--llm-api",
        args.llm_api,
        "--llm-model",
        args.llm_model,
        "--format",
        "json",
        "--out-json",
        str(report_path),
    ]
    if args.infer_hints:
        cmd.append("--infer-hints")

    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:  # pragma: no cover - runtime environment issue
        print("threat-thinker CLI not found on PATH.", file=sys.stderr)
        sys.exit(5)
    except subprocess.CalledProcessError as exc:  # pragma: no cover - CLI error bubble up
        print("threat-thinker think failed:", file=sys.stderr)
        if exc.stdout:
            print(exc.stdout, file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        sys.exit(exc.returncode)

    if not report_path.exists():
        print(f"Report file not found: {report_path}", file=sys.stderr)
        sys.exit(6)

    with report_path.open(encoding="utf-8") as handle:
        return json.load(handle)


def evaluate_scenario(
    scenario_dir: Path,
    scenario_data: Dict[str, Any],
    report: Dict[str, Any],
    similarity_engine: SimilarityEngine,
    similarity_threshold: float,
) -> Dict[str, Any]:
    expected_entries: List[Dict[str, Any]] = scenario_data.get("expected", [])
    actual_threats: List[Dict[str, Any]] = report.get("threats", [])
    evaluations = []

    for index, entry in enumerate(expected_entries):
        hit = match_expected(entry, index, actual_threats, similarity_engine, similarity_threshold)
        evaluations.append(
            {
                "id": entry.get("id"),
                "title": entry.get("title"),
                "matched": hit is not None,
                "matched_threat_id": hit.get("id") if hit else None,
                "matched_threat_title": hit.get("title") if hit else None,
            }
        )

    accepted = sum(1 for item in evaluations if item["matched"])
    outputs = len(actual_threats)
    gold = len(expected_entries)
    precision, recall, f1 = compute_metrics(accepted, outputs, gold)

    return {
        "scenario": scenario_dir.name,
        "diagram": scenario_data.get("diagram"),
        "accepted": accepted,
        "outputs": outputs,
        "gold": gold,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "matches": evaluations,
    }


def benchmark_mode(args: argparse.Namespace) -> None:
    bench_root = args.benchmark_root.resolve()
    repo_root = args.repo_root.resolve()
    report_dir = args.report_dir.resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    similarity_engine = load_similarity_engine(args.embedding_model)

    scenarios = discover_scenarios(bench_root)
    if args.scenarios:
        requested = set(args.scenarios)
        scenarios = [path for path in scenarios if path.name in requested]
        missing = requested - {path.name for path in scenarios}
        if missing:
            print(f"Unknown scenarios requested: {', '.join(sorted(missing))}", file=sys.stderr)
            sys.exit(7)

    if not scenarios:
        print("No scenarios with expected_threats.json found.", file=sys.stderr)
        sys.exit(8)

    scenario_results: List[Dict[str, Any]] = []
    total_accepted = 0
    total_outputs = 0
    total_gold = 0

    for scenario_dir in scenarios:
        expected_path = scenario_dir / "expected_threats.json"
        scenario_data = load_expected(expected_path)
        diagram_ref = scenario_data.get("diagram") or str(scenario_dir / "system.mmd")
        diagram_path = resolve_path(diagram_ref, repo_root)
        report_path = report_dir / f"{scenario_dir.name}.json"

        if not diagram_path.exists():
            print(f"Diagram not found for {scenario_dir.name}: {diagram_path}", file=sys.stderr)
            sys.exit(9)

        report = run_threat_thinker(diagram_path, report_path, args)
        evaluation = evaluate_scenario(
            scenario_dir,
            scenario_data,
            report,
            similarity_engine,
            args.similarity_threshold,
        )
        evaluation["diagram_path"] = str(diagram_path)
        evaluation["report_path"] = str(report_path)

        scenario_results.append(evaluation)
        total_accepted += evaluation["accepted"]
        total_outputs += evaluation["outputs"]
        total_gold += evaluation["gold"]

    total_precision, total_recall, total_f1 = compute_metrics(total_accepted, total_outputs, total_gold)
    decimals = args.decimals
    aggregate = {
        "accepted": total_accepted,
        "outputs": total_outputs,
        "gold": total_gold,
        "precision": round(total_precision, decimals),
        "recall": round(total_recall, decimals),
        "f1": round(total_f1, decimals),
    }

    if args.json:
        payload = {
            "scenarios": scenario_results,
            "totals": aggregate,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    fmt = f"{{:.{decimals}f}}"
    for scenario in scenario_results:
        matched_ids = [m["id"] for m in scenario["matches"] if m["matched"]]
        missing_ids = [m["id"] for m in scenario["matches"] if not m["matched"]]
        print(
            f"[{scenario['scenario']}] accepted={scenario['accepted']}/{scenario['gold']} "
            f"outputs={scenario['outputs']} precision={fmt.format(scenario['precision'])} "
            f"recall={fmt.format(scenario['recall'])} f1={fmt.format(scenario['f1'])}"
        )
        if matched_ids:
            print(f"  matched : {', '.join(matched_ids)}")
        if missing_ids:
            print(f"  missing : {', '.join(missing_ids)}")
        print(f"  report  : {scenario['report_path']}")

    print(
        f"TOTAL accepted={total_accepted}/{total_gold} outputs={total_outputs} "
        f"precision={fmt.format(total_precision)} recall={fmt.format(total_recall)} "
        f"f1={fmt.format(total_f1)}"
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.manual and (not args.llm_api or not args.llm_model):
        parser.error("--llm-api and --llm-model are required unless --manual is set.")

    if args.manual:
        manual_mode(args)
    else:
        benchmark_mode(args)


if __name__ == "__main__":
    main()
