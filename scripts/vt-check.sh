#!/usr/bin/env bash
# vt-check.sh — Upload binary to VirusTotal and check detection score
#
# Usage: ./scripts/vt-check.sh <binary>
# Requires: VIRUSTOTAL_API_KEY env var (free API key from virustotal.com)
#
# AI USAGE:
#   Run after every build to monitor AV detection trends.
#   Exit code 0 = 0 detections, 1 = some detections, 2 = error.
#   Output: JSON summary with detection count and engine names.
#
# Workflow:
#   scripts/vt-check.sh deploy/rsh.exe        # upload & poll
#   scripts/vt-check.sh .tmp/rsh-test.exe     # test build

set -euo pipefail

BINARY="${1:?Usage: vt-check.sh <binary>}"
VT_API="${VIRUSTOTAL_API_KEY:?Set VIRUSTOTAL_API_KEY env var}"

if [[ ! -f "$BINARY" ]]; then
    echo "ERROR: File not found: $BINARY" >&2
    exit 2
fi

echo "=== VirusTotal Check: $(basename "$BINARY") ==="
echo "Size: $(stat -c%s "$BINARY" 2>/dev/null || stat -f%z "$BINARY") bytes"
echo "SHA256: $(sha256sum "$BINARY" | cut -d' ' -f1)"
echo ""

# Step 1: Check if already analyzed (by hash)
HASH=$(sha256sum "$BINARY" | cut -d' ' -f1)
echo "Checking existing analysis for hash..."
EXISTING=$(curl -s --max-time 15 \
    -H "x-apikey: $VT_API" \
    "https://www.virustotal.com/api/v3/files/$HASH" 2>/dev/null)

if echo "$EXISTING" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['id'])" 2>/dev/null; then
    echo "Already analyzed — fetching results..."
    RESULT="$EXISTING"
else
    # Step 2: Upload
    echo "Uploading to VirusTotal..."
    UPLOAD=$(curl -s --max-time 120 \
        -H "x-apikey: $VT_API" \
        -F "file=@$BINARY" \
        "https://www.virustotal.com/api/v3/files")

    ANALYSIS_ID=$(echo "$UPLOAD" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
    if [[ -z "$ANALYSIS_ID" ]]; then
        echo "ERROR: Upload failed" >&2
        echo "$UPLOAD" >&2
        exit 2
    fi
    echo "Analysis ID: $ANALYSIS_ID"

    # Step 3: Poll for results (max 5 min)
    echo "Waiting for analysis..."
    for i in $(seq 1 30); do
        sleep 10
        STATUS=$(curl -s --max-time 15 \
            -H "x-apikey: $VT_API" \
            "https://www.virustotal.com/api/v3/analyses/$ANALYSIS_ID")

        DONE=$(echo "$STATUS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
s=d.get('data',{}).get('attributes',{}).get('status','')
print(s)" 2>/dev/null)

        if [[ "$DONE" == "completed" ]]; then
            break
        fi
        printf "."
    done
    echo ""

    # Fetch full file report
    RESULT=$(curl -s --max-time 15 \
        -H "x-apikey: $VT_API" \
        "https://www.virustotal.com/api/v3/files/$HASH")
fi

# Step 4: Parse results
python3 -c "
import sys, json

data = json.load(sys.stdin)
attrs = data.get('data', {}).get('attributes', {})
stats = attrs.get('last_analysis_stats', {})
results = attrs.get('last_analysis_results', {})

malicious = stats.get('malicious', 0)
suspicious = stats.get('suspicious', 0)
undetected = stats.get('undetected', 0)
total = malicious + suspicious + undetected + stats.get('harmless', 0) + stats.get('timeout', 0) + stats.get('failure', 0)

print(f'=== RESULTS ===')
print(f'Detections: {malicious} malicious, {suspicious} suspicious / {total} engines')
print(f'Score: {malicious + suspicious}/{total}')
print()

if malicious + suspicious > 0:
    print('Flagged by:')
    for engine, r in sorted(results.items()):
        cat = r.get('category', '')
        if cat in ('malicious', 'suspicious'):
            name = r.get('result', 'unknown')
            print(f'  - {engine}: {name} ({cat})')
    print()
    print(f'VirusTotal link: https://www.virustotal.com/gui/file/{attrs.get(\"sha256\", \"\")}')
    sys.exit(1)
else:
    print('CLEAN — no detections')
    sys.exit(0)
" <<< "$RESULT"
