#!/usr/bin/env bash
# Print out-of-band commands to install cua-ycwang system rules (udev, polkit, helper).
# IMPORTANT: This script NEVER runs sudo and NEVER writes to /etc/ or /usr/ automatically.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEM_DIR="$(cd "${SCRIPT_DIR}/../system" && pwd)"

UDEV_SRC="${SYSTEM_DIR}/udev/99-cua-uinput.rules"
POLKIT_POLICY_SRC="${SYSTEM_DIR}/polkit/io.github.yuchengwang.cua.policy"
POLKIT_RULES_SRC="${SYSTEM_DIR}/polkit/50-cua-ycwang-l1.rules"
HELPER_SRC="${SYSTEM_DIR}/libexec/cua-elevated-helper"

UDEV_DST="/etc/udev/rules.d/99-cua-uinput.rules"
POLKIT_POLICY_DST="/usr/share/polkit-1/actions/io.github.yuchengwang.cua.policy"
POLKIT_RULES_DST="/etc/polkit-1/rules.d/50-cua-ycwang-l1.rules"
HELPER_DST="/usr/local/libexec/cua-elevated-helper"

if [[ "${1:-}" == "--check" ]]; then
  missing=0
  for pair in \
    "${UDEV_SRC}:${UDEV_DST}" \
    "${POLKIT_POLICY_SRC}:${POLKIT_POLICY_DST}" \
    "${POLKIT_RULES_SRC}:${POLKIT_RULES_DST}" \
    "${HELPER_SRC}:${HELPER_DST}"; do
    src="${pair%%:*}"
    dst="${pair##*:}"
    if [[ -f "${dst}" ]] && cmp -s "${src}" "${dst}"; then
      echo "[OK] ${dst}"
    else
      echo "[MISSING/OUTDATED] ${dst}"
      missing=1
    fi
  done
  exit "${missing}"
fi

cat <<EOF
# Run the following commands out-of-band as an administrator to install
# cua-ycwang udev, polkit, and elevated helper rules:

sudo install -D -m 0644 "${UDEV_SRC}" "${UDEV_DST}"
sudo install -D -m 0644 "${POLKIT_POLICY_SRC}" "${POLKIT_POLICY_DST}"
sudo install -D -m 0644 "${POLKIT_RULES_SRC}" "${POLKIT_RULES_DST}"
sudo install -D -m 0755 "${HELPER_SRC}" "${HELPER_DST}"

# Reload udev and ensure the uinput kernel module is loaded:
sudo modprobe uinput
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=misc --sysname-match=uinput

# Optional: add your user to the 'input' group (requires re-login):
sudo usermod -aG input "\$USER"

# Verify installation afterwards:
"${SCRIPT_DIR}/doctor-linux.sh"
EOF
