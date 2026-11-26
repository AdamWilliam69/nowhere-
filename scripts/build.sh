#!/usr/bin/env bash
# Assemble modular sources under src/ into single-file nowhere-install.sh + nowhere-install.sh.sha256
# Usage:
#   ./scripts/build.sh            # build nowhere-install.sh and nowhere-install.sh.sha256
#   ./scripts/build.sh --check    # verify committed nowhere-install.sh & .sha256 match src/ (for CI)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="${REPO_ROOT}/nowhere-install.sh"
SHA_FILE="${REPO_ROOT}/nowhere-install.sh.sha256"
CHECK_ONLY=0
if [ "${1:-}" = "--check" ]; then
    CHECK_ONLY=1
fi

TMP_DIR="$(mktemp -d /tmp/nowhere-build.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT
TMP_OUT="${TMP_DIR}/nowhere-install.sh"

python3 - "$REPO_ROOT" "$TMP_OUT" << 'PY'
import os, re, sys

repo_root, out_path = sys.argv[1], sys.argv[2]
src_dir = os.path.join(repo_root, "src")

PARTS_BEFORE_I18N = [
    "00-header.sh",
]

PARTS_AFTER_I18N = [
    "20-lib/01-core.sh",
    "20-lib/02-csprng-sec.sh",
    "20-lib/03-firewall.sh",
    "20-lib/04-fail2ban.sh",
    "20-lib/05-maintain.sh",
    "30-modules/01-nowhere.sh",
    "30-modules/02-snell.sh",
    "30-modules/03-xray.sh",
    "30-modules/04-tuning.sh",
    "30-modules/05-realm.sh",
    "30-modules/06-xray-fwd.sh",
    "30-modules/07-proxy.sh",
    "99-main.sh",
]

def unescape_tsv(s: str) -> str:
    out = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            nxt = s[i + 1]
            if nxt == "t":
                out.append("\t")
            elif nxt == "n":
                out.append("\n")
            elif nxt == "\\":
                out.append("\\")
            else:
                out.append("\\" + nxt)
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)

def bash_sq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"

tsv_path = os.path.join(src_dir, "10-i18n/en.tsv")
i18n_entries = []
seen_keys = set()
dup_keys = []
with open(tsv_path, "r", encoding="utf-8") as f:
    for lineno, raw in enumerate(f, 1):
        line = raw.rstrip("\r\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            raise SystemExit(f"ERROR: {tsv_path}:{lineno}: expected 2 tab-separated fields, got {len(parts)}")
        k = unescape_tsv(parts[0])
        v = unescape_tsv(parts[1])
        if k in seen_keys:
            dup_keys.append((lineno, k))
        seen_keys.add(k)
        i18n_entries.append((k, v))

if dup_keys:
    for ln, k in dup_keys[:10]:
        print(f"ERROR: duplicate I18N key at {tsv_path}:{ln}: {k!r}", file=sys.stderr)
    raise SystemExit(f"Found {len(dup_keys)} duplicate I18N keys")

def read_part(rel: str) -> str:
    p = os.path.join(src_dir, rel)
    with open(p, "r", encoding="utf-8") as f:
        data = f.read()
    if data and not data.endswith("\n"):
        data += "\n"
    return data

chunks = []
for rel in PARTS_BEFORE_I18N:
    chunks.append(read_part(rel))

# Emit init_i18n_en()
i18n_block = [
    "declare -A I18N=()\n",
    "_I18N_INIT=0\n",
    "init_i18n_en() {\n",
    '    [ "$_I18N_INIT" = "1" ] && return 0\n',
    "    I18N=(\n",
]
for k, v in i18n_entries:
    i18n_block.append(f"        [{bash_sq(k)}]={bash_sq(v)}\n")
i18n_block.extend([
    "    )\n",
    "    _I18N_INIT=1\n",
    "}\n\n",
])
chunks.append("".join(i18n_block))

for rel in PARTS_AFTER_I18N:
    chunks.append(read_part(rel))

full_text = "".join(chunks)

# Validate every single-quoted/double-quoted static L '...' / L "..." call has an entry in en.tsv
# Only check static literals without unescaped $ variables
missing = set()
# Match $(L '...') and $(L "...") and standalone L '...' / L "..."
for m in re.finditer(r"""(?<![A-Za-z0-9_])L\s+(?:'([^']*)'|"([^"$`\\]*)")""", full_text):
    lit = m.group(1) if m.group(1) is not None else m.group(2)
    if lit and lit not in seen_keys:
        # Ignore comment lines / documentation examples that happen to match
        line_start = full_text.rfind("\n", 0, m.start()) + 1
        prefix = full_text[line_start:m.start()].lstrip()
        if prefix.startswith("#"):
            continue
        missing.add(lit)

if missing:
    for k in sorted(missing)[:30]:
        print(f"ERROR: missing I18N key in src/10-i18n/en.tsv: {k!r}", file=sys.stderr)
    raise SystemExit(f"Found {len(missing)} missing I18N keys")

with open(out_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(full_text)

print(f"Built {len(full_text.splitlines())} lines ({len(i18n_entries)} I18N entries, 0 duplicates, 0 missing)")
PY

bash -n "$TMP_OUT"
chmod 755 "$TMP_OUT"

TMP_SHA="${TMP_DIR}/nowhere-install.sh.sha256"
HASH="$(sha256sum "$TMP_OUT" | awk '{print $1}')"
printf '%s  nowhere-install.sh\n' "$HASH" > "$TMP_SHA"

if [ "$CHECK_ONLY" = "1" ]; then
    if [ ! -f "$OUT_FILE" ] || ! cmp -s "$TMP_OUT" "$OUT_FILE"; then
        echo "ERROR: nowhere-install.sh is out of sync with src/. Run ./scripts/build.sh" >&2
        exit 1
    fi
    if [ ! -f "$SHA_FILE" ] || ! cmp -s "$TMP_SHA" "$SHA_FILE"; then
        echo "ERROR: nowhere-install.sh.sha256 is out of sync. Run ./scripts/build.sh" >&2
        exit 1
    fi
    echo "OK: nowhere-install.sh and nowhere-install.sh.sha256 match src/ (sha256: ${HASH})"
    exit 0
fi

mv "$TMP_OUT" "$OUT_FILE"
mv "$TMP_SHA" "$SHA_FILE"
chmod 755 "$OUT_FILE"
chmod 644 "$SHA_FILE"
echo "Wrote ${OUT_FILE} and ${SHA_FILE} (sha256: ${HASH})"
