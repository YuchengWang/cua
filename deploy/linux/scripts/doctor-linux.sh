#!/usr/bin/env bash
# Read-only Linux environment diagnostic script for cua-ycwang.
set -euo pipefail

CONFIG_DIR="${CUA_YCWANG_CONFIG_DIR:-${HOME}/.config/cua-ycwang}"
HOME_DIR="${CUA_YCWANG_HOME:-${HOME}/.cua-ycwang}"
NAMESPACE="${CUA_DRIVER_STATE_NAMESPACE:-cua-ycwang}"

pass_count=0
warn_count=0
fail_count=0

ok() {
  echo "[PASS] $1"
  pass_count=$((pass_count + 1))
}

warn() {
  echo "[WARN] $1"
  warn_count=$((warn_count + 1))
}

fail() {
  echo "[FAIL] $1"
  fail_count=$((fail_count + 1))
}

echo "=== cua-ycwang Linux Doctor ==="
echo "Namespace : ${NAMESPACE}"
echo "Config dir: ${CONFIG_DIR}"
echo "Home dir  : ${HOME_DIR}"
echo

# 1. User config & isolation
if [[ -f "${CONFIG_DIR}/config.json" ]]; then
  ok "User config present: ${CONFIG_DIR}/config.json"
else
  warn "User config missing: ${CONFIG_DIR}/config.json (run deploy-user-config.sh)"
fi

if [[ -f "${CONFIG_DIR}/x11_profiles.json" ]]; then
  ok "X11 profiles present: ${CONFIG_DIR}/x11_profiles.json"
else
  warn "X11 profiles missing: ${CONFIG_DIR}/x11_profiles.json"
fi

# 2. X11 virtual desktop tools
for bin in Xvfb openbox x11vnc autocutsel; do
  if command -v "${bin}" >/dev/null 2>&1; then
    ok "Binary available: ${bin}"
  else
    fail "Missing required X11 binary: ${bin}"
  fi
done

# 3. /dev/uinput and input group
if [[ -e /dev/uinput ]]; then
  if [[ -r /dev/uinput && -w /dev/uinput ]]; then
    ok "/dev/uinput exists and is readable/writable by $(id -un)"
  else
    warn "/dev/uinput exists but is not rw by $(id -un) (check 'input' group or udev rule)"
  fi
else
  warn "/dev/uinput not present (run 'sudo modprobe uinput' out-of-band)"
fi

if id -nG "$(id -un)" | tr ' ' '\n' | grep -qx "input"; then
  ok "User $(id -un) is in 'input' group"
else
  warn "User $(id -un) is NOT in 'input' group"
fi

# 4. System rules
for sys_file in \
  /etc/udev/rules.d/99-cua-uinput.rules \
  /usr/share/polkit-1/actions/io.github.yuchengwang.cua.policy \
  /etc/polkit-1/rules.d/50-cua-ycwang-l1.rules \
  /usr/local/libexec/cua-elevated-helper; do
  if [[ -e "${sys_file}" ]]; then
    ok "Installed: ${sys_file}"
  else
    warn "Not installed: ${sys_file} (run install-system-rules.sh to view commands)"
  fi
done

echo
echo "Summary: ${pass_count} passed, ${warn_count} warnings, ${fail_count} failed"
if [[ "${fail_count}" -gt 0 ]]; then
  exit 1
fi
