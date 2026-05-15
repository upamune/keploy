#!/bin/bash
set -Eeuo pipefail

source "$GITHUB_WORKSPACE/.github/workflows/test_workflow_scripts/test-iid.sh"

cleanup() {
  sudo pkill -9 keploy 2>/dev/null || true
  sudo pkill -9 -f "[p]ython3 app.py" 2>/dev/null || true
}
trap cleanup EXIT

cd "$GITHUB_WORKSPACE/.github/workflows/test_workflow_scripts/python/freeze_time"

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

rm -rf keploy keploy.yml
"$RECORD_BIN" config --generate

send_request() {
  local keploy_pid="$1"
  for _ in $(seq 1 40); do
    if curl -fsS --max-time 3 http://127.0.0.1:8091/health >/dev/null; then
      curl -fsS --max-time 5 http://127.0.0.1:8091/now >/dev/null
      sudo kill -INT "$keploy_pid" 2>/dev/null || true
      return 0
    fi
    sleep 1
  done

  echo "::error::freeze-time app did not become ready"
  tail -200 record_logs.txt || true
  sudo kill -INT "$keploy_pid" 2>/dev/null || true
  return 1
}

"$RECORD_BIN" record -c "python3 app.py" --generateGithubActions=false > record_logs.txt 2>&1 &
KEPLOY_PID=$!
send_request "$KEPLOY_PID"
wait "$KEPLOY_PID" || true
sleep 2

if grep -q 'WARNING: DATA RACE' record_logs.txt; then
  echo "::error::data race detected during record"
  tail -200 record_logs.txt
  exit 1
fi
if grep -q 'ERROR' record_logs.txt; then
  echo "::error::error logged during record"
  tail -200 record_logs.txt
  exit 1
fi

expected_record_now=$(python - <<'PY'
import pathlib
import re
body = pathlib.Path("keploy/test-set-0/tests/get-now-1.yaml").read_text()
match = re.search(r'\{"now":"([^"]+)"\}', body)
if not match:
    raise SystemExit("could not find recorded /now response timestamp")
print(match.group(1))
PY
)

"$REPLAY_BIN" test -c "EXPECTED_RECORD_NOW=$expected_record_now python3 app.py" --delay 5 --freeze-time --generateGithubActions=false 2>&1 | tee test_logs.txt

latest_run=$(ls -1dt ./keploy/reports/test-run-* 2>/dev/null | head -n1 || true)
if [ -z "$latest_run" ]; then
  echo "::error::no test-run report directory found"
  exit 1
fi

for report in "$latest_run"/test-set-*-report.yaml; do
  status=$(grep '^status:' "$report" | awk '{print $2}')
  if [ "$status" != "PASSED" ]; then
    echo "::error::$report status=$status"
    cat "$report"
    exit 1
  fi
done

echo "PASS: Python datetime.now() replayed with recorded wall-clock time"
