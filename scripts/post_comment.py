"""Poster AI-funnene som en kommentar paa pull requesten."""
import html
import json
import os
import re
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
MARKER = "<!-- ai-security-review -->"
BOT_LOGIN = "github-actions[bot]"
MAX_FIELD = 1500
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def github_request(method, url, token, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ai-security-review",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
    return json.loads(raw) if raw else None


def clean(value):
    """Modelltekst er upaalitelig: hindre HTML, lenker, bilder og @-mentions."""
    text = str(value)[:MAX_FIELD]
    text = html.escape(text)
    text = text.replace("@", "@\u200b")
    text = text.replace("](", "]\u200b(")
    text = text.replace("`", "'")
    return text


def clean_code(value):
    """Til kodeblokker: fjern backticks saa modellen ikke kan bryte ut av blokken."""
    return str(value)[:MAX_FIELD].replace("`", "'")


def build_body(findings):
    lines = [MARKER, "## 🤖 AI-sikkerhetsgjennomgang", ""]
    if not findings:
        lines.append("Ingen sikkerhetsproblemer funnet i denne endringen. ✅")
        lines.append("")
    else:
        lines.append("Fant **%d** mulige sikkerhetsproblemer:" % len(findings))
        lines.append("")
        for i, item in enumerate(findings, 1):
            severity = str(item.get("severity", "ukjent")).lower()
            icon = SEVERITY_ICON.get(severity, "⚪")
            lines.append("### %s %d. %s" % (icon, i, clean(item["title"])))
            lines.append("**Fil:** %s, linje %s · **%s** · Alvorlighet: **%s**" % (
                clean(item["file"]), clean(item.get("line", "?")),
                clean(item.get("cwe", "ukjent CWE")), clean(severity)))
            lines.append("")
            lines.append(clean(item["explanation"]))
            if item.get("fix"):
                lines.append("")
                lines.append("**Forslag til fiks:**")
                lines.append("```text")
                lines.append(clean_code(item["fix"]))
                lines.append("```")
            lines.append("")
    lines.append("---")
    lines.append("_Generert av en spr\u00e5kmodell. Funnene kan v\u00e6re feil eller "
                 "ufullstendige, og erstatter ikke manuell gjennomgang._")
    return "\n".join(lines)


def find_existing_comment(repo, pr, token):
    url = "%s/repos/%s/issues/%s/comments?per_page=100" % (API, repo, pr)
    for comment in github_request("GET", url, token) or []:
        author = (comment.get("user") or {}).get("login")
        if author == BOT_LOGIN and MARKER in (comment.get("body") or ""):
            return comment["id"]
    return None


def main():
    if len(sys.argv) != 2:
        print("Bruk: python3 post_comment.py <findings.json>", file=sys.stderr)
        return 1

    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("REPO", "")
    pr = os.environ.get("PR_NUMBER", "")

    if not token:
        print("Feil: GITHUB_TOKEN mangler.", file=sys.stderr)
        return 1
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        print("Feil: ugyldig REPO-verdi.", file=sys.stderr)
        return 1
    if not pr.isdigit():
        print("Feil: ugyldig PR_NUMBER.", file=sys.stderr)
        return 1

    try:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            findings = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print("Feil: kunne ikke lese funnene: %s" % e, file=sys.stderr)
        return 1
    if not isinstance(findings, list):
        print("Feil: funnene har feil format.", file=sys.stderr)
        return 1

    body = {"body": build_body(findings)}

    try:
        existing = find_existing_comment(repo, pr, token)
        if existing:
            url = "%s/repos/%s/issues/comments/%s" % (API, repo, existing)
            github_request("PATCH", url, token, body)
            print("Oppdaterte eksisterende kommentar.")
        else:
            url = "%s/repos/%s/issues/%s/comments" % (API, repo, pr)
            github_request("POST", url, token, body)
            print("Postet ny kommentar.")
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print("Advarsel: mangler skrivetilgang (PR fra en fork?). "
                  "Hopper over kommentaren.", file=sys.stderr)
            return 0
        detail = e.read().decode("utf-8", errors="replace")[:500]
        print("GitHub API-feil: HTTP %d %s\n%s" % (e.code, e.reason, detail),
              file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print("Nettverksfeil: %s" % e.reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
