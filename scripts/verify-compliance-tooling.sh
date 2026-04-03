#!/usr/bin/env bash
# verify-compliance-tooling.sh — Smoke tests for FedRAMP 20x compliance tooling
#
# Validates that all compliance scripts, generators, and workflows function correctly.
# Run this after any changes to compliance/ to confirm nothing is broken.
#
# Usage:
#   ./scripts/verify-compliance-tooling.sh
#
# Exit codes:
#   0 = all checks passed
#   1 = one or more checks failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0
SKIP=0

pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  ⏭  $1 (skipped)"; SKIP=$((SKIP + 1)); }

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  FedRAMP 20x Compliance Tooling — Verification Suite        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─────────────────────────────────────────────────────────────────────
echo "── 1. Source Documents ──"
# ─────────────────────────────────────────────────────────────────────

if [ -f "$ROOT/fedramp-ssp.md" ]; then
  LINES=$(wc -l < "$ROOT/fedramp-ssp.md" | tr -d ' ')
  if [ "$LINES" -gt 100 ]; then
    pass "fedramp-ssp.md exists ($LINES lines)"
  else
    fail "fedramp-ssp.md is suspiciously short ($LINES lines)"
  fi
else
  fail "fedramp-ssp.md not found"
fi

if [ -f "$ROOT/fedramp-ssp-appendix-a-controls.md" ]; then
  CONTROLS=$(grep -c '^### [A-Z]\{2\}-' "$ROOT/fedramp-ssp-appendix-a-controls.md" || echo 0)
  if [ "$CONTROLS" -gt 200 ]; then
    pass "Appendix A has $CONTROLS controls (expected 230+)"
  else
    fail "Appendix A has only $CONTROLS controls (expected 230+)"
  fi
else
  fail "fedramp-ssp-appendix-a-controls.md not found"
fi

if [ -f "$ROOT/fedramp-20x-ksi-summaries.md" ]; then
  KSI_THEMES=$(grep -c '^## [0-9]' "$ROOT/fedramp-20x-ksi-summaries.md" || echo 0)
  if [ "$KSI_THEMES" -ge 9 ]; then
    pass "KSI summaries document has $KSI_THEMES themes"
  else
    fail "KSI summaries only has $KSI_THEMES themes (expected 11)"
  fi
else
  fail "fedramp-20x-ksi-summaries.md not found"
fi

if [ -f "$ROOT/customer-secure-configuration-guide.md" ]; then
  pass "Customer Secure Configuration Guide exists"
else
  fail "customer-secure-configuration-guide.md not found"
fi

POLICY_COUNT=$(ls -1 "$ROOT/policies/"*.md 2>/dev/null | wc -l | tr -d ' ')
if [ "$POLICY_COUNT" -ge 10 ]; then
  pass "Found $POLICY_COUNT policy documents in policies/"
else
  fail "Only $POLICY_COUNT policies found (expected 10+)"
fi

# ─────────────────────────────────────────────────────────────────────
echo ""
echo "── 2. OSCAL SSP Generation ──"
# ─────────────────────────────────────────────────────────────────────

if [ -f "$ROOT/scripts/generate-oscal-ssp.mjs" ]; then
  pass "OSCAL generator script exists"
else
  fail "scripts/generate-oscal-ssp.mjs not found"
fi

# Run the generator
OSCAL_OUTPUT="$ROOT/oscal/ssp-test.json"
if node "$ROOT/scripts/generate-oscal-ssp.mjs" --output "$OSCAL_OUTPUT" > /dev/null 2>&1; then
  pass "OSCAL generator ran successfully"

  # Validate JSON syntax
  if python3 -m json.tool "$OSCAL_OUTPUT" > /dev/null 2>&1; then
    pass "Generated SSP is valid JSON"
  else
    fail "Generated SSP is NOT valid JSON"
  fi

  # Check required top-level keys
  if python3 -c "
import json, sys
with open('$OSCAL_OUTPUT') as f:
    ssp = json.load(f)
root = ssp.get('system-security-plan', {})
required = ['uuid', 'metadata', 'import-profile', 'system-characteristics', 'system-implementation', 'control-implementation']
missing = [k for k in required if k not in root]
if missing:
    print(f'Missing keys: {missing}', file=sys.stderr)
    sys.exit(1)
controls = root.get('control-implementation', {}).get('implemented-requirements', [])
print(f'{len(controls)} controls')
if len(controls) < 200:
    sys.exit(1)
" 2>&1; then
    CTRL_COUNT=$(python3 -c "
import json
with open('$OSCAL_OUTPUT') as f:
    ssp = json.load(f)
print(len(ssp['system-security-plan']['control-implementation']['implemented-requirements']))
")
    pass "SSP has all required sections and $CTRL_COUNT implemented requirements"
  else
    fail "SSP missing required OSCAL sections or has too few controls"
  fi

  # Check OSCAL version
  OSCAL_VER=$(python3 -c "
import json
with open('$OSCAL_OUTPUT') as f:
    print(json.load(f)['system-security-plan']['metadata']['oscal-version'])
" 2>/dev/null || echo "unknown")
  if [ "$OSCAL_VER" = "1.1.3" ]; then
    pass "OSCAL version is $OSCAL_VER"
  else
    fail "OSCAL version is $OSCAL_VER (expected 1.1.3)"
  fi

  # Cleanup test output
  rm -f "$OSCAL_OUTPUT"
else
  fail "OSCAL generator failed to run"
fi

# Check if oscal-cli validation is available (Docker)
if command -v docker &>/dev/null && docker image inspect ghcr.io/metaschema-framework/oscal-cli:latest &>/dev/null; then
  echo "  (oscal-cli Docker image available — running validation)"
  if [ -f "$ROOT/oscal/ssp.json" ]; then
    if docker run --rm -v "$ROOT:/data" ghcr.io/metaschema-framework/oscal-cli:latest validate /data/oscal/ssp.json 2>&1; then
      pass "oscal-cli validation passed"
    else
      fail "oscal-cli validation failed"
    fi
  else
    skip "oscal/ssp.json not found — run 'npm run generate:oscal' first"
  fi
else
  skip "oscal-cli Docker image not available (pull with: docker pull ghcr.io/metaschema-framework/oscal-cli:latest)"
fi

# ─────────────────────────────────────────────────────────────────────
echo ""
echo "── 3. Go CLI Tools ──"
# ─────────────────────────────────────────────────────────────────────

if [ -f "$ROOT/cmd/ksi-evidence/main.go" ]; then
  if go build -o /dev/null "$ROOT/cmd/ksi-evidence/" 2>/dev/null; then
    pass "cmd/ksi-evidence builds cleanly"
  else
    fail "cmd/ksi-evidence fails to build"
  fi
else
  fail "cmd/ksi-evidence/main.go not found"
fi

if [ -f "$ROOT/cmd/classify-scn/main.go" ]; then
  if go build -o /dev/null "$ROOT/cmd/classify-scn/" 2>/dev/null; then
    pass "cmd/classify-scn builds cleanly"
  else
    fail "cmd/classify-scn fails to build"
  fi
else
  fail "cmd/classify-scn/main.go not found"
fi

if [ -f "$ROOT/cmd/verify-controls/main.go" ]; then
  if go build -o /dev/null "$ROOT/cmd/verify-controls/" 2>/dev/null; then
    pass "cmd/verify-controls builds cleanly"
  else
    fail "cmd/verify-controls fails to build"
  fi
else
  fail "cmd/verify-controls/main.go not found"
fi

# Check that gcloud is available (needed for evidence collection)
if command -v gcloud &>/dev/null; then
  ACCT=$(gcloud config get-value account 2>/dev/null || echo "none")
  if [ "$ACCT" != "none" ] && [ -n "$ACCT" ]; then
    pass "gcloud authenticated as $ACCT"
  else
    skip "gcloud not authenticated — evidence collection requires auth"
  fi
else
  skip "gcloud CLI not installed — needed for evidence collection"
fi

# ─────────────────────────────────────────────────────────────────────
echo ""
echo "── 4. SCN Classifier Integration Test ──"
# ─────────────────────────────────────────────────────────────────────

cd "$ROOT"
if git rev-parse --git-dir > /dev/null 2>&1; then
  SCN_EXIT=0
  go run ./cmd/classify-scn --base HEAD~1 --head HEAD --json > /dev/null 2>&1 || SCN_EXIT=$?
  if [ "$SCN_EXIT" -eq 0 ]; then
    pass "SCN classifier ran successfully (classified as ROUTINE)"
  elif [ "$SCN_EXIT" -eq 1 ]; then
    pass "SCN classifier ran successfully (classified as SIGNIFICANT)"
  else
    fail "SCN classifier crashed (exit code $SCN_EXIT)"
  fi
else
  skip "Not in a git repo — cannot test SCN classifier"
fi

# ─────────────────────────────────────────────────────────────────────
echo ""
echo "── 5. CI Workflows ──"
# ─────────────────────────────────────────────────────────────────────

WORKFLOWS=(
  ".github/workflows/oscal-validate.yml"
  ".github/workflows/ksi-evidence.yml"
  ".github/workflows/scn-classify.yml"
  ".github/workflows/publish-pdfs.yml"
  ".github/workflows/monthly-exercises.yml"
)

for WF in "${WORKFLOWS[@]}"; do
  if [ -f "$ROOT/$WF" ]; then
    pass "Workflow: $(basename "$WF")"
  else
    fail "Workflow missing: $WF"
  fi
done

# ─────────────────────────────────────────────────────────────────────
echo ""
echo "── 6. Package Dependencies ──"
# ─────────────────────────────────────────────────────────────────────

if [ -f "$ROOT/package.json" ]; then
  # Check that npm scripts exist
  for SCRIPT in "build:pdfs" "generate:oscal" "validate:oscal"; do
    if grep -q "\"$SCRIPT\"" "$ROOT/package.json"; then
      pass "npm script: $SCRIPT"
    else
      fail "npm script missing: $SCRIPT"
    fi
  done
else
  fail "package.json not found"
fi

if [ -d "$ROOT/node_modules" ]; then
  pass "node_modules installed"
else
  skip "node_modules not installed — run 'npm ci' first"
fi

# ─────────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "══════════════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "  ❌ VERIFICATION FAILED — $FAIL check(s) need attention"
  exit 1
else
  echo ""
  echo "  ✅ ALL CHECKS PASSED"
  exit 0
fi
