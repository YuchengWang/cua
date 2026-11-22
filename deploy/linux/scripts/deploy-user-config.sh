#!/usr/bin/env bash
# Deploy isolated cua-ycwang user configuration to $CUA_YCWANG_CONFIG_DIR (default ~/.config/cua-ycwang).
# Never uses sudo and never writes outside user-owned directories.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_USER_DIR="$(cd "${SCRIPT_DIR}/../user" && pwd)"
TARGET_CONFIG_DIR="${CUA_YCWANG_CONFIG_DIR:-${HOME}/.config/cua-ycwang}"
TARGET_HOME_DIR="${CUA_YCWANG_HOME:-${HOME}/.cua-ycwang}"
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      echo "Usage: $(basename "$0") [--dry-run]"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

echo "[cua-ycwang] Source user config: ${REPO_USER_DIR}"
echo "[cua-ycwang] Target config dir : ${TARGET_CONFIG_DIR}"
echo "[cua-ycwang] Target home dir   : ${TARGET_HOME_DIR}"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "[cua-ycwang] Dry-run mode: no files will be modified."
  find "${REPO_USER_DIR}" -type f | sort | sed "s|^${REPO_USER_DIR}/|  -> ${TARGET_CONFIG_DIR}/|"
  exit 0
fi

mkdir -p "${TARGET_CONFIG_DIR}" "${TARGET_HOME_DIR}"

while IFS= read -r -d '' src_file; do
  rel_path="${src_file#${REPO_USER_DIR}/}"
  dst_file="${TARGET_CONFIG_DIR}/${rel_path}"
  mkdir -p "$(dirname "${dst_file}")"
  if [[ -f "${dst_file}" ]] && ! cmp -s "${src_file}" "${dst_file}"; then
    cp -a "${dst_file}" "${dst_file}.bak.$(date +%Y%m%d%H%M%S)"
  fi
  cp -a "${src_file}" "${dst_file}"
done < <(find "${REPO_USER_DIR}" -type f -print0 | sort -z)

# Ensure systemd user unit is linked if ~/.config/systemd/user exists or can be created
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
if [[ -f "${TARGET_CONFIG_DIR}/systemd/cua-ycwang.service" ]]; then
  mkdir -p "${SYSTEMD_USER_DIR}"
  ln -sfn "${TARGET_CONFIG_DIR}/systemd/cua-ycwang.service" "${SYSTEMD_USER_DIR}/cua-ycwang.service"
fi

echo "[cua-ycwang] User configuration deployed successfully."
