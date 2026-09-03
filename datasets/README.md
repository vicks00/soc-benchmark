# Source captures

Scenarios are compiled from adversary-emulation captures published by
[OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) under the MIT license, at commit
`be0e82209deae630529fa2fa289dacf360b52351` (2021-08-02), retrieved 2026-08-01. All paths below are
under `datasets/atomic/windows/` in that repository.

| Archive | Upstream path |
|---|---|
| `cmd_mshta_vbscript_execute_psh.zip` | `defense_evasion/host/` |
| `covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip` | `credential_access/host/` |
| `covenant_wmi_wbemcomn_dll_hijack.zip` | `lateral_movement/host/` |
| `empire_mimikatz_logonpasswords.zip` | `credential_access/host/` |
| `empire_msbuild_dcerpc_wmi_smb.zip` | `lateral_movement/host/` |
| `empire_psexec_dcerpc_tcp_svcctl.zip` | `lateral_movement/network/` |
| `empire_uac_shellapi_fodhelper.zip` | `privilege_escalation/host/` |
| `psh_lsass_memory_dump_comsvcs.zip` | `credential_access/host/` |

Digests are in `SHA256SUMS`. Each `scenarios/*/spec.json` names the archive it was built from.

The archives are not committed. Fetch them to rebuild a scenario or to audit that the committed
contexts still match a fresh build:

```bash
bash tools/fetch_datasets.sh
python tools/validate.py --require-captures
```

Both verify against `SHA256SUMS` and fail on a mismatch. Running and scoring the benchmark does not
need them.

## License of the source captures

The compiled contexts under `scenarios/` are derived from this material, so the MIT notice travels
with them. This is the only copy of it in the repository.

```
MIT License

Copyright (c) 2021 Open Threat Research Forge

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
