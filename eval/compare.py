"""Sammenligner AI-funn og Semgrep-funn mot en fasit og regner ut presisjon/recall.

Bruk: python3 eval/compare.py eval/ground_truth.json findings.json semgrep.json

Vurderingen gjoeres paa filnivaa:
  TP = saarbar fil som verktoeyet flagget
  FN = saarbar fil som verktoeyet ikke flagget
  FP = trygg fil som verktoeyet flagget
  TN = trygg fil som verktoeyet ikke flagget
I tillegg telles det om verktoeyet oppga riktig CWE for de saarbare filene.
"""
import json
import os
import re
import sys

CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print("Advarsel: kunne ikke lese %s (%s)" % (path, e), file=sys.stderr)
        return default


def normalize_path(path):
    path = str(path).replace("\\", "/")
    for prefix in ("./", "a/", "b/"):
        if path.startswith(prefix):
            path = path[len(prefix):]
    return path


def extract_cwes(value):
    if isinstance(value, list):
        text = " ".join(str(v) for v in value)
    else:
        text = str(value or "")
    return {c.upper() for c in CWE_RE.findall(text)}


def ai_by_file(findings):
    result = {}
    for item in findings if isinstance(findings, list) else []:
        if not isinstance(item, dict):
            continue
        path = normalize_path(item.get("file", ""))
        result.setdefault(path, set()).update(extract_cwes(item.get("cwe")))
    return result


def semgrep_by_file(data):
    result = {}
    results = data.get("results", []) if isinstance(data, dict) else []
    for item in results:
        path = normalize_path(item.get("path", ""))
        metadata = (item.get("extra") or {}).get("metadata") or {}
        result.setdefault(path, set()).update(extract_cwes(metadata.get("cwe")))
    return result


def score(truth, flagged):
    tp = fp = fn = tn = cwe_ok = 0
    rows = []
    for path, case in sorted(truth.items()):
        hit = path in flagged
        cwes = flagged.get(path, set())
        expected = {c.upper() for c in case["cwe"]}
        if case["vulnerable"]:
            if hit:
                tp += 1
                right_cwe = bool(cwes & expected)
                cwe_ok += right_cwe
                rows.append((path, "TP", ", ".join(sorted(cwes)) or "-", right_cwe))
            else:
                fn += 1
                rows.append((path, "FN", "-", False))
        else:
            if hit:
                fp += 1
                rows.append((path, "FP", ", ".join(sorted(cwes)) or "-", None))
            else:
                tn += 1
                rows.append((path, "TN", "-", None))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "cwe_ok": cwe_ok,
            "precision": precision, "recall": recall, "f1": f1, "rows": rows}


def build_report(truth, ai, semgrep):
    lines = ["## Sammenligning mot fasit", ""]
    lines.append("| Verktøy | TP | FP | FN | TN | Presisjon | Recall | F1 | Riktig CWE |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for name, s in (("AI-bot", ai), ("Semgrep", semgrep)):
        lines.append("| %s | %d | %d | %d | %d | %.0f %% | %.0f %% | %.2f | %d av %d |" % (
            name, s["tp"], s["fp"], s["fn"], s["tn"],
            s["precision"] * 100, s["recall"] * 100, s["f1"], s["cwe_ok"], s["tp"]))
    lines.append("")
    lines.append("### Per testfil")
    lines.append("")
    lines.append("| Fil | Fasit | AI-bot | Semgrep |")
    lines.append("|---|---|---|---|")
    ai_rows = {r[0]: r for r in ai["rows"]}
    sg_rows = {r[0]: r for r in semgrep["rows"]}
    for path, case in sorted(truth.items()):
        def cell(row):
            label, cwes, right = row[1], row[2], row[3]
            if label == "TP":
                return "✅ TP (%s)%s" % (cwes, "" if right else " ⚠️ feil CWE")
            if label == "FN":
                return "❌ FN"
            if label == "FP":
                return "⚠️ FP (%s)" % cwes
            return "✅ TN"
        lines.append("| %s | %s | %s | %s |" % (
            os.path.basename(path), case["type"], cell(ai_rows[path]), cell(sg_rows[path])))
    return "\n".join(lines)


def main():
    if len(sys.argv) != 4:
        print("Bruk: python3 compare.py <fasit.json> <findings.json> <semgrep.json>",
              file=sys.stderr)
        return 1
    truth = load_json(sys.argv[1], None)
    if not isinstance(truth, dict):
        print("Feil: fasiten mangler eller har feil format.", file=sys.stderr)
        return 1

    ai = score(truth, ai_by_file(load_json(sys.argv[2], [])))
    semgrep = score(truth, semgrep_by_file(load_json(sys.argv[3], {})))
    report = build_report(truth, ai, semgrep)
    print(report)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(report + "\n")

    with open("comparison.json", "w", encoding="utf-8") as f:
        json.dump({"ai": {k: v for k, v in ai.items() if k != "rows"},
                   "semgrep": {k: v for k, v in semgrep.items() if k != "rows"}},
                  f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
