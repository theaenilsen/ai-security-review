"""Maaler hvor stabil AI-boten er over flere kjoeringer paa samme kode.

Bruk: python3 eval/stability.py eval/ground_truth.json runs/findings_1.json runs/findings_2.json ...

Skriver ut:
  - presisjon, recall og F1 for hver kjoering
  - gjennomsnitt, laveste og hoeyeste verdi
  - hvor mange av kjoeringene som flagget hver testfil
"""
import os
import sys

from compare import ai_by_file, load_json, score


def main():
    if len(sys.argv) < 3:
        print("Bruk: python3 stability.py <fasit.json> <findings_1.json> [findings_2.json ...]",
              file=sys.stderr)
        return 1

    truth = load_json(sys.argv[1], None)
    if not isinstance(truth, dict):
        print("Feil: fasiten mangler eller har feil format.", file=sys.stderr)
        return 1

    runs = []
    for path in sys.argv[2:]:
        flagged = ai_by_file(load_json(path, []))
        runs.append((flagged, score(truth, flagged)))
    n = len(runs)

    lines = ["## Stabilitet over %d kjøringer" % n, ""]
    lines.append("| Kjøring | TP | FP | FN | TN | Presisjon | Recall | F1 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for i, (_, s) in enumerate(runs, 1):
        lines.append("| %d | %d | %d | %d | %d | %.0f %% | %.0f %% | %.2f |" % (
            i, s["tp"], s["fp"], s["fn"], s["tn"],
            s["precision"] * 100, s["recall"] * 100, s["f1"]))
    lines.append("")

    lines.append("| Mål | Snitt | Lavest | Høyest |")
    lines.append("|---|---|---|---|")
    for key, label, pct in (("precision", "Presisjon", True), ("recall", "Recall", True),
                            ("f1", "F1", False)):
        values = [s[key] for _, s in runs]
        fmt = "%.0f %%" if pct else "%.2f"
        mult = 100 if pct else 1
        lines.append("| %s | %s | %s | %s |" % (
            label, fmt % (sum(values) / n * mult), fmt % (min(values) * mult),
            fmt % (max(values) * mult)))
    lines.append("")

    lines.append("### Hvor ofte ble hver fil flagget?")
    lines.append("")
    lines.append("| Fil | Fasit | Flagget | Vurdering |")
    lines.append("|---|---|---|---|")
    unstable = 0
    for path, case in sorted(truth.items()):
        hits = sum(1 for flagged, _ in runs if path in flagged)
        if 0 < hits < n:
            verdict = "⚠️ Ustabil"
            unstable += 1
        elif case["vulnerable"]:
            verdict = "✅ Alltid funnet" if hits == n else "❌ Aldri funnet"
        else:
            verdict = "✅ Aldri flagget" if hits == 0 else "❌ Alltid falsk alarm"
        lines.append("| %s | %s | %d av %d | %s |" % (
            os.path.basename(path), case["type"], hits, n, verdict))
    lines.append("")
    lines.append("**%d av %d filer fikk ulikt svar mellom kjøringene.**" % (unstable, len(truth)))

    report = "\n".join(lines)
    print(report)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(report + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
