#!/usr/bin/env bash
# CYBER-SEC flow-matrix validator (SEC-040) — run on the TARGET host after
# applying nftables.conf. Checks each matrix row with real probes and prints
# a PASS/FAIL table. Read-only against the platform: uses only connectivity
# probes (nc/timeout), no data is written to the platform.
#
# Usage: sudo ./validate_flows.sh  (override zones with env: MGMT_IP, APP_IP, LAB_IP)
set -u
MGMT_IP="${MGMT_IP:-10.40.0.10}"
APP_IP="${APP_IP:-10.41.0.10}"
LAB_IP="${LAB_IP:-10.42.0.10}"
T=3

probe() { # probe <src-if or - > dst > port  (runs from this host; use ssh -J for cross-host)
  local dst="$1" port="$2"
  timeout "$T" bash -c "exec 3<>/dev/tcp/$dst/$port" 2>/dev/null
}

check() { # check <description> <expect: allow|deny> <dst> <port>
  local desc="$1" expect="$2" dst="$3" port="$4" got
  if probe "$dst" "$port"; then got=allow; else got=deny; fi
  if [ "$got" = "$expect" ]; then printf 'PASS  %-52s expect %-5s got %-5s\n' "$desc" "$expect" "$got"
  else printf 'FAIL  %-52s expect %-5s got %-5s\n' "$desc" "$expect" "$got"; FI=1; fi
}
FI=0

echo "CYBER-SEC flow matrix validation ($(date -u +%FT%TZ))"
check "app -> lab-targets :8080 (exercise hooks)"   allow "$LAB_IP" 8080
check "lab-targets -> app :8080 (must be denied)"   deny  "$APP_IP" 8080
check "lab-targets -> app :22    (must be denied)"  deny  "$APP_IP" 22
check "lab-targets -> mgmt :22   (must be denied)"  deny  "$MGMT_IP" 22
check "app :8080 from app zone (health)"            allow "$APP_IP" 8080
check "random closed port (default deny)"           deny  "$APP_IP" 65000

[ "$FI" = 0 ] && echo "RESULT: PASS — matrix enforced" || echo "RESULT: FAIL — see FAIL lines"
exit "$FI"
