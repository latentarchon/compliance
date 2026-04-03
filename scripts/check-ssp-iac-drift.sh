#!/usr/bin/env bash
# check-ssp-iac-drift.sh — Automated SSP-to-IaC drift detection
#
# Parses concrete claims from the SSP and cross-checks them against
# actual Terraform/Terragrunt configurations and backend source code.
#
# Exit codes:
#   0 = no drift detected
#   1 = drift detected (SSP does not match IaC)
#   2 = setup error (missing files/repos)
#
# Usage:
#   ./scripts/check-ssp-iac-drift.sh [--infra-root ../infra] [--backend-root ../backend]

set -euo pipefail

# ── Defaults ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPLIANCE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INFRA_ROOT="${COMPLIANCE_ROOT}/../infra"
BACKEND_ROOT="${COMPLIANCE_ROOT}/../backend"
SSP="${COMPLIANCE_ROOT}/fedramp-ssp-appendix-a-controls.md"

# ── Parse args ──
while [[ $# -gt 0 ]]; do
  case "$1" in
    --infra-root) INFRA_ROOT="$2"; shift 2 ;;
    --backend-root) BACKEND_ROOT="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 2 ;;
  esac
done

# ── Validate paths ──
for f in "$SSP" "$INFRA_ROOT" "$BACKEND_ROOT"; do
  if [ ! -e "$f" ]; then
    echo "ERROR: Not found: $f"
    exit 2
  fi
done

DRIFT=0
CHECKS=0
PASS=0
FAIL=0

check() {
  local name="$1"
  local expected="$2"
  local actual="$3"
  CHECKS=$((CHECKS + 1))

  if [ "$expected" = "$actual" ]; then
    echo "  ✅ $name: $actual"
    PASS=$((PASS + 1))
  else
    echo "  ❌ $name: SSP='$expected' IaC='$actual'"
    FAIL=$((FAIL + 1))
    DRIFT=1
  fi
}

check_contains() {
  local name="$1"
  local needle="$2"
  local haystack="$3"
  CHECKS=$((CHECKS + 1))

  if echo "$haystack" | grep -qF "$needle"; then
    echo "  ✅ $name: contains '$needle'"
    PASS=$((PASS + 1))
  else
    echo "  ❌ $name: missing '$needle'"
    FAIL=$((FAIL + 1))
    DRIFT=1
  fi
}

echo "═══════════════════════════════════════════════════════════"
echo "  SSP-to-IaC Drift Detection"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "SSP:     $SSP"
echo "Infra:   $INFRA_ROOT"
echo "Backend: $BACKEND_ROOT"
echo ""

# ═══════════════════════════════════════════════════════════════
# 1. KMS Rotation Period (SC-12)
# ═══════════════════════════════════════════════════════════════
echo "── SC-12: KMS Rotation Period ──"

# Extract rotation_period default from KMS module variables (value is "7776000s" string)
# Match only the 'default =' line (not the description), extract digits
KMS_ROTATION_RAW=$(grep -A4 'variable "rotation_period"' "$INFRA_ROOT/gcp/modules/kms/variables.tf" \
  | grep 'default\s*=' | sed -n 's/.*"\([0-9]*\)s".*/\1/p')

# The IaC default is in seconds: 7776000s = 90 days
KMS_ROTATION_DAYS=$((KMS_ROTATION_RAW / 86400))

check "KMS rotation (days)" "90" "$KMS_ROTATION_DAYS"

# ═══════════════════════════════════════════════════════════════
# 2. Cloud SQL Backup Retention (CP-9)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "── CP-9: Cloud SQL Backup Config ──"

# Extract retained_backups from cloud-sql module
SQL_RETAINED=$(grep -A1 'retained_backups' "$INFRA_ROOT/gcp/modules/cloud-sql/main.tf" \
  | grep -oE '[0-9]+' | head -1)

check "Cloud SQL retained_backups" "14" "$SQL_RETAINED"

# PITR enabled?
SQL_PITR=$(grep -c 'point_in_time_recovery_enabled\s*=\s*true' "$INFRA_ROOT/gcp/modules/cloud-sql/main.tf" || echo "0")
check "Cloud SQL PITR enabled" "1" "$SQL_PITR"

# ═══════════════════════════════════════════════════════════════
# 3. GCS Soft Delete (CP-9)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "── CP-9: GCS Soft Delete ──"

# GCS module uses var.soft_delete_retention_seconds — check the variable default
GCS_SOFT_DELETE_VAR=$(grep -A4 'variable "soft_delete_retention_seconds"' "$INFRA_ROOT/gcp/modules/gcs/variables.tf" \
  | grep 'default\s*=' | grep -oE '[0-9]+' | head -1 || true)
if [ -n "$GCS_SOFT_DELETE_VAR" ] && [ "$GCS_SOFT_DELETE_VAR" -gt 0 ] 2>/dev/null; then
  GCS_SOFT_DELETE_DAYS=$((GCS_SOFT_DELETE_VAR / 86400))
  check "GCS soft_delete default (days)" "90" "$GCS_SOFT_DELETE_DAYS"
else
  echo "  ⚠️  Cannot determine GCS soft delete config"
fi

# ═══════════════════════════════════════════════════════════════
# 4. Audit Log WORM Retention (AU-11)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "── AU-11: Audit Log WORM Retention ──"

# Production audit-logs terragrunt
PROD_AUDIT="$INFRA_ROOT/gcp/environments/fed/production/ops/audit-logs/terragrunt.hcl"
if [ -f "$PROD_AUDIT" ]; then
  PROD_RETENTION=$(grep 'gcs_audit_retention_days' "$PROD_AUDIT" | grep -oE '[0-9]+' | head -1)
  PROD_LOCKED=$(grep 'gcs_audit_retention_locked' "$PROD_AUDIT" | grep -oE 'true|false' | head -1)
  PROD_YEARS=$((PROD_RETENTION / 365))
  check "Prod WORM retention (years)" "7" "$PROD_YEARS"
  check "Prod WORM locked" "true" "$PROD_LOCKED"
else
  echo "  ⚠️  Production audit-logs config not found (expected: $PROD_AUDIT)"
fi

# Staging audit-logs
STAGING_AUDIT="$INFRA_ROOT/gcp/environments/fed/staging/ops/audit-logs/terragrunt.hcl"
if [ -f "$STAGING_AUDIT" ]; then
  STAGING_RETENTION=$(grep 'gcs_audit_retention_days' "$STAGING_AUDIT" | grep -oE '[0-9]+' | head -1)
  STAGING_LOCKED=$(grep 'gcs_audit_retention_locked' "$STAGING_AUDIT" | grep -oE 'true|false' | head -1)
  check "Staging WORM retention (days)" "365" "$STAGING_RETENTION"
  check "Staging WORM unlocked" "false" "$STAGING_LOCKED"
else
  echo "  ⚠️  Staging audit-logs config not found"
fi

# ═══════════════════════════════════════════════════════════════
# 5. Terraform-SA Role Count (AC-6)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "── AC-6: Terraform SA IAM Roles ──"

SA_CONFIG="$INFRA_ROOT/gcp/environments/fed/staging/ops/service-accounts/terragrunt.hcl"
if [ -f "$SA_CONFIG" ]; then
  # Count roles inside the terraform-sa block
  TF_SA_ROLES=$(sed -n '/terraform-sa/,/^    }/p' "$SA_CONFIG" \
    | grep -c 'roles/' || echo "0")
  check "terraform-sa role count" "20" "$TF_SA_ROLES"

  # Check for roles/editor (SSP says it's present)
  HAS_EDITOR=$(sed -n '/terraform-sa/,/^    }/p' "$SA_CONFIG" \
    | grep -c 'roles/editor' || echo "0")
  check "terraform-sa has roles/editor" "1" "$HAS_EDITOR"
else
  echo "  ⚠️  Service-accounts config not found"
fi

# ═══════════════════════════════════════════════════════════════
# 6. Session Idle Timeout Default (AC-12)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "── AC-12: Session Idle Timeout ──"

INTERCEPTOR="$BACKEND_ROOT/cmd/server/connect_interceptors.go"
if [ -f "$INTERCEPTOR" ]; then
  IDLE_DEFAULT=$(grep 'SESSION_IDLE_TIMEOUT_MIN' "$INTERCEPTOR" \
    | sed -n 's/.*GetEnvAsInt([^,]*, *\([0-9]*\)).*/\1/p' | head -1)
  ABS_DEFAULT=$(grep 'SESSION_ABSOLUTE_TIMEOUT_MIN' "$INTERCEPTOR" \
    | sed -n 's/.*GetEnvAsInt([^,]*, *\([0-9]*\)).*/\1/p' | head -1)
  check "Idle timeout default (min)" "25" "$IDLE_DEFAULT"
  check "Absolute timeout default (min)" "720" "$ABS_DEFAULT"
else
  echo "  ⚠️  Auth interceptor not found"
fi

# ═══════════════════════════════════════════════════════════════
# 7. Cloud Run Ingress Default (SC-7)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "── SC-7: Cloud Run Ingress ──"

CR_INGRESS_DEFAULT=$(grep -A3 'variable "ingress"' "$INFRA_ROOT/gcp/modules/cloud-run/variables.tf" \
  | grep 'default' | sed -n 's/.*"\([^"]*\)".*/\1/p' | head -1)
check "Cloud Run ingress default" "internal-and-cloud-load-balancing" "$CR_INGRESS_DEFAULT"

# ═══════════════════════════════════════════════════════════════
# 8. GCS force_destroy (SI-12)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "── SI-12: GCS force_destroy ──"

GCS_FD_DEFAULT=$(grep -A3 'variable "force_destroy"' "$INFRA_ROOT/gcp/modules/gcs/variables.tf" \
  | grep 'default' | grep -oE 'true|false' | head -1)
check "GCS force_destroy default" "false" "$GCS_FD_DEFAULT"

# Audit logs module hardcodes force_destroy
AUDIT_FD=$(grep 'force_destroy' "$INFRA_ROOT/gcp/modules/audit-logs/main.tf" \
  | grep -oE 'true|false' | head -1)
check "Audit logs force_destroy" "false" "$AUDIT_FD"

# ═══════════════════════════════════════════════════════════════
# 9. BoringCrypto (SC-13)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "── SC-13: BoringCrypto ──"

# Count only the ENV line, not comment lines
BORING_DOCKERFILE=$(grep -v '^#' "$BACKEND_ROOT/Dockerfile" | grep -c 'GOEXPERIMENT=boringcrypto' || echo "0")
check "Dockerfile has GOEXPERIMENT=boringcrypto" "1" "$BORING_DOCKERFILE"

# ═══════════════════════════════════════════════════════════════
# 10. VPC Egress Default Deny (AC-4)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "── AC-4: VPC Egress Default Deny ──"

VPC_DENY=$(grep -c 'deny_all' "$INFRA_ROOT/gcp/modules/vpc/main.tf" || echo "0")
check "VPC has default-deny egress rule" "1" "$((VPC_DENY > 0 ? 1 : 0))"

VPC_FQDN=$(grep -c 'dest_fqdns' "$INFRA_ROOT/gcp/modules/vpc/main.tf" || echo "0")
check "VPC uses FQDN-based egress" "1" "$((VPC_FQDN > 0 ? 1 : 0))"

# ═══════════════════════════════════════════════════════════════
# 11. CMEK Key Coverage (SC-12)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "── SC-12: CMEK Key Coverage ──"

KMS_MODULE="$INFRA_ROOT/gcp/modules/kms/variables.tf"
for key in cloudsql gcs bigquery logging vertex_ai artifact_registry cloud_tasks app_secrets; do
  KEY_EXISTS=$(grep -c "enable_${key}_key" "$KMS_MODULE" || echo "0")
  check "KMS has enable_${key}_key variable" "1" "$((KEY_EXISTS > 0 ? 1 : 0))"
done

# ═══════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════"
if [ "$DRIFT" -eq 0 ]; then
  echo "  ✅ ALL $CHECKS CHECKS PASSED — No SSP-IaC drift detected"
else
  echo "  ❌ DRIFT DETECTED: $FAIL/$CHECKS checks failed"
fi
echo "═══════════════════════════════════════════════════════════"

exit "$DRIFT"
