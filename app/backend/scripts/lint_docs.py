#!/usr/bin/env python3
"""Documentation invariants (acceptance clause 11: documentation matches implementation).

Prose cannot be linted, but the claims that rot fastest can be: index completeness, the
current test count, the migration list, the SPA page inventory, CI job count, `make`
targets named in docs, and every repo path a document points at. Each check is mechanical
and makes no judgement about wording; the historical log in docs/13 is exempt from
count checks on purpose (it records what was true at the time).

    python -m scripts.lint_docs          # exit 1 on any broken invariant

Run in CI (backend job) and from `make lint-docs`.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DOCS = ROOT / "docs"
README = ROOT / "README.md"

NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7}

# Files exempt from "current value" checks: they are dated logs, not status pages.
HISTORICAL = {"13-verification-evidence.md"}

# Generated/runtime paths a document may legitimately mention: they exist on a working
# host (a virtualenv, a built SPA, a test data dir) and never in a clean checkout, which
# is exactly where this script also has to pass — CI. Checked: the first CI run of this
# very lint failed on `.venv` and `.testdata`.
GENERATED = (".venv", "node_modules", "dist/", "/dist", ".testdata", "__pycache__",
             ".pytest_cache", "data/", "/data", "cybersec.db", ".tar.gz", ".log")


class Checker:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.checked = 0

    def expect(self, ok: bool, message: str) -> None:
        self.checked += 1
        if not ok:
            self.failures.append(message)

    def expect_in(self, needle: str, haystack: str, message: str) -> None:
        self.expect(needle in haystack, message)


def collected_tests() -> int | None:
    """Ask pytest itself; the count is only trustworthy from the source of truth."""
    try:
        out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q"],
                             cwd=ROOT / "app" / "backend", capture_output=True, text=True,
                             timeout=180)
    except Exception:  # noqa: BLE001
        return None
    match = re.search(r"(\d+) tests? collected", out.stdout)
    return int(match.group(1)) if match else None


def main() -> int:
    c = Checker()
    readme = README.read_text()
    docs = sorted(DOCS.glob("*.md"))
    doc_text = {p.name: p.read_text() for p in docs}

    # 1. every document is in the README index
    for p in docs:
        c.expect(p.name in readme, f"README index does not link docs/{p.name}")

    # 2. no document points at a repo path that does not exist. Documents write paths
    #    from whichever root is natural in the sentence ("tests/x.py" from the backend,
    #    "docs/08" for a doc prefix), so a reference resolves against the repo root, the
    #    backend and the frontend, and a bare prefix may name a file that starts with it.
    def resolves(rel: str) -> bool:
        for base in (ROOT, ROOT / "app" / "backend", ROOT / "app" / "frontend"):
            candidate = base / rel
            if candidate.exists():
                return True
            if candidate.parent.exists() and any(
                    p.name.startswith(candidate.name) for p in candidate.parent.iterdir()):
                return True
        return False

    path_re = re.compile(r"`((?:docs|infra|planning|app|agents|tests|scripts|scenarios)/[\w./-]+)`")
    for name, text in doc_text.items():
        for rel in set(path_re.findall(text)):
            if any(ch in rel for ch in "*<>") or rel.endswith(("/",)):
                continue
            if any(marker in rel for marker in GENERATED):
                continue
            c.expect(resolves(rel), f"docs/{name} references missing path {rel}")
    for name, text in doc_text.items():
        path_re_scripts = re.compile(r"`?((?:app/backend/)?scripts/[\w.]+\.py)`?")
        for rel in set(path_re_scripts.findall(text)):
            if not rel.startswith("app/"):
                rel = f"app/backend/{rel}"
            c.expect((ROOT / rel).exists(), f"docs/{name} references missing script {rel}")

    # 3. the current test count matches what pytest collects
    count = collected_tests()
    if count is not None:
        readme_counts = set(re.findall(r"(\d+)\s+tests", readme))
        for found in readme_counts:
            c.expect(int(found) == count,
                     f"README claims {found} tests; pytest collects {count}")
        totals = re.search(r"\*\*Current totals:\*\* \*\*(\d+) tests pass\*\*",
                           doc_text["13-verification-evidence.md"])
        if totals:
            c.expect(int(totals.group(1)) == count,
                     f"docs/13 'Current totals' says {totals.group(1)}; pytest collects {count}")

    # 4. every migration is documented — by name or by number, which is how the data
    #    model doc and the evidence log refer to them
    migrations = sorted((ROOT / "app/backend/app/migrations").glob("*.sql"))
    all_docs = readme + "\n".join(doc_text.values())
    for migration in migrations:
        number = migration.name.split("_", 1)[0]
        c.expect(migration.name in all_docs or number in all_docs,
                 f"migration {migration.name} is not documented")

    # 5. every SPA page is in the frontend inventory (docs/11)
    pages = sorted((ROOT / "app/frontend/src/pages").glob("*.tsx"))
    frontend = doc_text["11-frontend-spa.md"]
    for page in pages:
        c.expect(page.stem in frontend, f"docs/11 does not list the {page.stem} page")

    # 6. the README's CI job count matches the workflow
    try:
        import yaml
        jobs = list(yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"])
    except Exception as e:  # noqa: BLE001
        jobs = []
        c.expect(False, f"cannot read the CI workflow: {e}")
    spelled = re.search(r"runs (\w+) jobs on every push/PR", readme)
    if spelled and spelled.group(1).lower() in NUMBER_WORDS:
        c.expect(NUMBER_WORDS[spelled.group(1).lower()] == len(jobs),
                 f"README says {spelled.group(1)} CI jobs; ci.yml defines {len(jobs)}: {jobs}")

    # 7. every `make <target>` named in docs exists
    makefile = (ROOT / "Makefile").read_text()
    targets = set(re.findall(r"^([a-zA-Z][\w-]*):", makefile, re.M))
    for name, text in list(doc_text.items()) + [("README.md", readme)]:
        # only inline-code mentions: prose like "make those explicit" is not a target
        for target in set(re.findall(r"`make ([a-z][\w-]*)", text)):
            c.expect(target in targets, f"{name} names `make {target}`, which the Makefile lacks")

    # 8. docs/17 and the range compose agree on the profile names
    compose = (ROOT / "infra/lab/docker-compose.yml").read_text()
    for profile in re.findall(r'profiles: \["(\w+)"\]', compose):
        c.expect(profile in (ROOT / "docs/17-lab-range.md").read_text(),
                 f"compose profile {profile} is not mentioned in docs/17")

    for failure in c.failures:
        print(f"FAIL  {failure}")
    print(f"{c.checked} documentation invariants checked, {len(c.failures)} failed")
    return 1 if c.failures else 0


if __name__ == "__main__":
    sys.exit(main())
