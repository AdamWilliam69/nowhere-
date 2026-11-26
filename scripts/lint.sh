#!/usr/bin/env bash
# Static analysis, syntax check, build drift check, and security invariants for nowhere-install.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO_ROOT}/nowhere-install.sh"

echo "==> 1/5 Build drift & I18N check"
"${REPO_ROOT}/scripts/build.sh" --check

echo "==> 2/5 Bash syntax check (bash -n)"
bash -n "$SCRIPT"
for f in "${REPO_ROOT}"/scripts/*.sh "${REPO_ROOT}"/tests/*.sh; do
    [ -f "$f" ] || continue
    bash -n "$f"
done

echo "==> 3/5 Security invariants check"
# Forbid chown -R (symlink traversal risk)
if grep -En '(^|[^#a-zA-Z0-9_])chown[[:space:]]+(-[a-zA-Z]*R|--recursive)' "$SCRIPT" | grep -v '^[0-9]*:[[:space:]]*#'; then
    echo "ERROR: Recursive 'chown -R' is forbidden; iterate safely over non-symlink targets." >&2
    exit 1
fi

# Forbid direct curl invocations outside secure_curl (ignore comments, echo/warn strings, package lists, command -v)
python3 - "$SCRIPT" << 'PY'
import re, sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    lines = f.readlines()

in_secure_curl = False
bad = []
for idx, line in enumerate(lines, 1):
    s = line.strip()
    if s.startswith("secure_curl()"):
        in_secure_curl = True
        continue
    if in_secure_curl:
        if s == "}":
            in_secure_curl = False
        continue
    if not s or s.startswith("#"):
        continue
    # Match actual command invocation of curl (start of statement / after && || ; | ( )
    if re.search(r'(?:^|[;&|(]\s*)curl\s+-', line):
        # Ignore echo/warn/printf string literals
        if re.match(r'^\s*(echo|warn|info|error|success|printf|\[)', line):
            continue
        bad.append((idx, line.rstrip()))

if bad:
    for ln, txt in bad:
        print(f"ERROR: Direct curl call outside secure_curl at line {ln}: {txt}", file=sys.stderr)
    sys.exit(1)
print("OK: 0 forbidden chown -R, 0 direct curl calls outside secure_curl")
PY

echo "==> 4/5 ShellCheck (-s bash -S warning, 0 warnings allowed)"
if ! command -v shellcheck >/dev/null 2>&1; then
    echo "ERROR: shellcheck not installed" >&2
    exit 1
fi

TMP_DIR="$(mktemp -d /tmp/nowhere-lint.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT
STUB_SCRIPT="${TMP_DIR}/nowhere-install-stub.sh"

# Replace the 2,100-entry I18N associative array body with a stub so shellcheck finishes in ~2s
python3 - "$SCRIPT" "$STUB_SCRIPT" << 'PY'
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    lines = f.readlines()
out = []
skip = False
for line in lines:
    if line.startswith("init_i18n_en() {"):
        out.append("init_i18n_en() { _I18N_INIT=1; }\n")
        skip = True
        continue
    if skip:
        if line.rstrip("\n") == "}":
            skip = False
        continue
    out.append(line)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.writelines(out)
PY

shellcheck -s bash -S warning "$STUB_SCRIPT"
shellcheck -s bash -S warning "${REPO_ROOT}"/scripts/*.sh "${REPO_ROOT}"/tests/*.sh

echo "==> 5/5 Executable permissions check"
[ -x "$SCRIPT" ] || { echo "ERROR: nowhere-install.sh must be executable" >&2; exit 1; }
echo "ALL LINT CHECKS PASSED (0 errors, 0 warnings)"
