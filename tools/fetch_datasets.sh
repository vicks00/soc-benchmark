#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/datasets}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"

declare -a FILES=(
  "credential_access/host/psh_lsass_memory_dump_comsvcs.zip"
  "credential_access/host/empire_mimikatz_logonpasswords.zip"
  "credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip"
  "privilege_escalation/host/empire_uac_shellapi_fodhelper.zip"
  "lateral_movement/host/covenant_wmi_wbemcomn_dll_hijack.zip"
  "lateral_movement/host/empire_msbuild_dcerpc_wmi_smb.zip"
  "defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip"
  "lateral_movement/network/empire_psexec_dcerpc_tcp_svcctl.zip"
)

mkdir -p "$TARGET"
for f in "${FILES[@]}"; do
  name="$(basename "$f")"
  echo "==> $name"
  curl -fsSL "$RAW/$f" -o "$TARGET/$name"
done

python3 - "$TARGET" "$ROOT/datasets/SHA256SUMS" <<'PY'
import hashlib
import sys
from pathlib import Path

target, manifest = map(Path, sys.argv[1:])
for line in manifest.read_text().splitlines():
    expected, name = line.split(maxsplit=1)
    actual = hashlib.sha256((target / name).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"checksum mismatch: {name}")
print("All capture checksums match.")
PY

echo
echo "Downloaded ${#FILES[@]} captures to $TARGET"
echo "Verify nothing drifted:  python tools/build_scenarios.py --check"
