package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// KMSCheck verifies KMS key ring and crypto key accessibility.
type KMSCheck struct {
	projectID string
	region    string
	keyRing   string
	keyName   string
}

// NewKMSCheck creates a KMS key accessibility check.
func NewKMSCheck(projectID, region, keyRing, keyName string) *KMSCheck {
	return &KMSCheck{
		projectID: projectID,
		region:    region,
		keyRing:   keyRing,
		keyName:   keyName,
	}
}

// Run executes the KMS key verification.
func (c *KMSCheck) Run(ctx context.Context) Result {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return Result{
			Category:    "Cloud KMS",
			Name:        fmt.Sprintf("Key Accessibility (%s/%s)", c.keyRing, c.keyName),
			Description: "Verify KMS key ring and crypto key are accessible with rotation configured",
			Status:      StatusFail,
			Details:     fmt.Sprintf("Failed to create KMS client: %v", err),
			Control:     "SC-12",
		}
	}
	defer client.Close()

	var findings []string
	allPassed := true

	// Check key ring
	keyRingName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", c.projectID, c.region, c.keyRing)
	kr, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{Name: keyRingName})
	if err != nil {
		return Result{
			Category:    "Cloud KMS",
			Name:        fmt.Sprintf("Key Accessibility (%s/%s)", c.keyRing, c.keyName),
			Description: "Verify KMS key ring and crypto key are accessible with rotation configured",
			Status:      StatusFail,
			Details:     fmt.Sprintf("Failed to get key ring %s: %v", c.keyRing, err),
			Control:     "SC-12",
		}
	}
	findings = append(findings, fmt.Sprintf("✅ Key ring accessible: %s", kr.Name))

	// Check crypto key
	cryptoKeyName := fmt.Sprintf("%s/cryptoKeys/%s", keyRingName, c.keyName)
	key, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: cryptoKeyName})
	if err != nil {
		findings = append(findings, fmt.Sprintf("❌ Failed to get crypto key %s: %v", c.keyName, err))
		allPassed = false
	} else {
		findings = append(findings, fmt.Sprintf("✅ Crypto key accessible: %s", key.Name))

		// Check rotation period
		if rp, ok := key.GetRotationSchedule().(*kmspb.CryptoKey_RotationPeriod); ok && rp.RotationPeriod != nil {
			days := rp.RotationPeriod.Seconds / 86400
			findings = append(findings, fmt.Sprintf("✅ Key rotation period: %d days", days))
			if days > 365 {
				findings = append(findings, "⚠️ Rotation period exceeds 365 days (NIST recommends annual rotation)")
			}
		} else {
			findings = append(findings, "⚠️ No automatic rotation configured")
		}

		// Check next rotation time
		if key.NextRotationTime != nil {
			nextRotation := key.NextRotationTime.AsTime()
			findings = append(findings, fmt.Sprintf("✅ Next rotation: %s", nextRotation.Format(time.RFC3339)))
		}

		// Check primary version state
		if key.Primary != nil {
			state := key.Primary.State.String()
			if key.Primary.State == kmspb.CryptoKeyVersion_ENABLED {
				findings = append(findings, fmt.Sprintf("✅ Primary version state: %s", state))
			} else {
				findings = append(findings, fmt.Sprintf("❌ Primary version state: %s (expected ENABLED)", state))
				allPassed = false
			}

			// Check algorithm
			if key.Primary.Algorithm != kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
				findings = append(findings, fmt.Sprintf("✅ Algorithm: %s", key.Primary.Algorithm.String()))
			}
		}

		// Check purpose
		findings = append(findings, fmt.Sprintf("✅ Key purpose: %s", key.Purpose.String()))
	}

	status := StatusPass
	if !allPassed {
		status = StatusFail
	}

	return Result{
		Category:    "Cloud KMS",
		Name:        fmt.Sprintf("Key Accessibility (%s/%s)", c.keyRing, c.keyName),
		Description: "Verify KMS key ring and crypto key are accessible with rotation configured",
		Status:      status,
		Details:     strings.Join(findings, "\n"),
		Control:     "SC-12",
	}
}
