#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

PAIRS=(
  "docs/LINUX_X11_VIRTUAL_SCREEN_PLAN.md:docs/LINUX_X11_VIRTUAL_SCREEN_PLAN.zh.md"
  "docs/LINUX_X11_PERMISSIONS.md:docs/LINUX_X11_PERMISSIONS.zh.md"
)

fail=0

echo "[check-docs-sync] Checking bilingual document pairs and heading symmetry..."
for pair in "${PAIRS[@]}"; do
  en="${pair%%:*}"
  zh="${pair##*:}"

  if [[ ! -f "$en" ]]; then
    echo "ERROR: Missing English doc: $en" >&2
    fail=1
    continue
  fi
  if [[ ! -f "$zh" ]]; then
    echo "ERROR: Missing Chinese doc: $zh" >&2
    fail=1
    continue
  fi

  en_h2=$(grep -cE '^## ' "$en" || true)
  zh_h2=$(grep -cE '^## ' "$zh" || true)
  en_h3=$(grep -cE '^### ' "$en" || true)
  zh_h3=$(grep -cE '^### ' "$zh" || true)

  if [[ "$en_h2" != "$zh_h2" ]] || [[ "$en_h3" != "$zh_h3" ]]; then
    echo "ERROR: Heading count mismatch between $en (H2=$en_h2, H3=$en_h3) and $zh (H2=$zh_h2, H3=$zh_h3)" >&2
    fail=1
  else
    echo "  OK: $en <-> $zh (H2=$en_h2, H3=$en_h3)"
  fi
done

if [[ ! -f "docs/CHANGELOG_YCWANG.md" ]]; then
  echo "ERROR: Missing docs/CHANGELOG_YCWANG.md" >&2
  fail=1
fi

# When comparing against a base ref (e.g. --diff-base HEAD~1 or staged changes),
# enforce that code/deploy changes are accompanied by changelog + bilingual doc updates.
DIFF_BASE="${1:-}"
changed_files=""
if [[ -n "$DIFF_BASE" ]]; then
  changed_files=$(git diff --name-only "$DIFF_BASE")
else
  changed_files=$(git diff --cached --name-only)
fi

if [[ -n "$changed_files" ]]; then
  code_touched=0
  changelog_touched=0
  doc_en_touched=0
  doc_zh_touched=0

  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if [[ "$f" == libs/cua-driver/* ]] || [[ "$f" == deploy/linux/* && "$f" != "deploy/linux/scripts/check-docs-sync.sh" ]]; then
      code_touched=1
    fi
    [[ "$f" == "docs/CHANGELOG_YCWANG.md" ]] && changelog_touched=1
    if [[ "$f" == docs/LINUX_X11_*.md && "$f" != *.zh.md ]]; then
      doc_en_touched=1
    fi
    if [[ "$f" == docs/LINUX_X11_*.zh.md ]]; then
      doc_zh_touched=1
    fi
  done <<< "$changed_files"

  if [[ "$code_touched" -eq 1 ]]; then
    if [[ "$changelog_touched" -eq 0 ]]; then
      echo "ERROR: Code/deploy changed without updating docs/CHANGELOG_YCWANG.md" >&2
      fail=1
    fi
    if [[ "$doc_en_touched" -ne "$doc_zh_touched" ]]; then
      echo "ERROR: Bilingual docs must be updated in pairs (.md and .zh.md)" >&2
      fail=1
    fi
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo "[check-docs-sync] FAILED" >&2
  exit 1
fi

echo "[check-docs-sync] PASSED"
