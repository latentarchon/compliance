package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type EvidenceEntry struct {
	ControlID    string   `json:"control-id"`
	Tier         string   `json:"evidence-tier"`
	Status       string   `json:"implementation-status"`
	Baseline     string   `json:"baseline"`
	Components   []string `json:"component-uuids"`
	NarrativeLen int      `json:"narrative-length"`
	Narrative    string   `json:"narrative"`
}

type TierSummary struct {
	GeneratedAt    string         `json:"generated-at"`
	Baseline       string         `json:"baseline"`
	TotalControls  int            `json:"total-controls"`
	Verified       int            `json:"verified"`
	Templated      int            `json:"templated"`
	Manual         int            `json:"manual"`
	VerifiedPct    float64        `json:"verified-pct"`
	TemplatedPct   float64        `json:"templated-pct"`
	ManualPct      float64        `json:"manual-pct"`
	ByFamily       map[string]int `json:"by-family"`
	ByFamilyByTier map[string]map[string]int `json:"by-family-by-tier"`
}

func generateEvidence(controls []ControlDef, facts *InfraFacts, baseline, outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("mkdir evidence: %w", err)
	}

	filtered := filterControlsByBaseline(controls, baseline)

	var verified, templated, manual []EvidenceEntry
	familyCounts := map[string]int{}
	familyTierCounts := map[string]map[string]int{}

	for _, c := range filtered {
		narrative := c.NarrativeFn(facts)
		components := c.ComponentUUIDs
		if len(components) == 0 {
			components = []string{thisSystem}
		}

		entry := EvidenceEntry{
			ControlID:    c.ID,
			Tier:         c.EvidenceTier,
			Status:       c.ImplStatus,
			Baseline:     c.Baseline,
			Components:   components,
			NarrativeLen: len(narrative),
			Narrative:    narrative,
		}

		family := controlFamily(c.ID)
		familyCounts[family]++
		if familyTierCounts[family] == nil {
			familyTierCounts[family] = map[string]int{}
		}
		familyTierCounts[family][c.EvidenceTier]++

		switch c.EvidenceTier {
		case "verified":
			verified = append(verified, entry)
		case "manual":
			manual = append(manual, entry)
		default:
			templated = append(templated, entry)
		}
	}

	if err := writeJSON(filepath.Join(outDir, "verified-controls.json"), verified); err != nil {
		return err
	}

	if err := writeMarkdownEvidence(filepath.Join(outDir, "templated-controls.md"), "Templated Controls", templated); err != nil {
		return err
	}

	if err := writeMarkdownEvidence(filepath.Join(outDir, "manual-controls.md"), "Manual Controls", manual); err != nil {
		return err
	}

	total := len(filtered)
	summary := TierSummary{
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		Baseline:       baseline,
		TotalControls:  total,
		Verified:       len(verified),
		Templated:      len(templated),
		Manual:         len(manual),
		VerifiedPct:    pct(len(verified), total),
		TemplatedPct:   pct(len(templated), total),
		ManualPct:      pct(len(manual), total),
		ByFamily:       familyCounts,
		ByFamilyByTier: familyTierCounts,
	}

	if err := writeSummaryMarkdown(filepath.Join(outDir, "tier-summary.md"), summary); err != nil {
		return err
	}

	return writeJSON(filepath.Join(outDir, "tier-summary.json"), summary)
}

func filterControlsByBaseline(controls []ControlDef, level string) []ControlDef {
	allowed := map[string]bool{"moderate": true, "": true}
	if level == "high" || level == "il5" {
		allowed["high"] = true
	}
	if level == "il5" {
		allowed["il5"] = true
	}
	var out []ControlDef
	for _, c := range controls {
		bl := c.Baseline
		if bl == "" {
			bl = "moderate"
		}
		if allowed[bl] {
			out = append(out, c)
		}
	}
	return out
}

func controlFamily(id string) string {
	parts := strings.SplitN(id, "-", 2)
	if len(parts) > 0 {
		return strings.ToUpper(parts[0])
	}
	return "OTHER"
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	return os.WriteFile(path, data, 0644)
}

func writeMarkdownEvidence(path, title string, entries []EvidenceEntry) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s\n\n", title))
	b.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().UTC().Format("2006-01-02")))
	b.WriteString(fmt.Sprintf("Total: %d controls\n\n", len(entries)))

	currentFamily := ""
	for _, e := range entries {
		family := controlFamily(e.ControlID)
		if family != currentFamily {
			b.WriteString(fmt.Sprintf("\n## %s Family\n\n", family))
			currentFamily = family
		}
		b.WriteString(fmt.Sprintf("### %s\n\n", strings.ToUpper(e.ControlID)))
		b.WriteString(fmt.Sprintf("**Status:** %s | **Baseline:** %s\n\n", e.Status, e.Baseline))
		b.WriteString(e.Narrative)
		b.WriteString("\n\n---\n\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func writeSummaryMarkdown(path string, s TierSummary) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Evidence Tier Summary\n\n"))
	b.WriteString(fmt.Sprintf("Generated: %s  \n", s.GeneratedAt))
	b.WriteString(fmt.Sprintf("Baseline: %s  \n", s.Baseline))
	b.WriteString(fmt.Sprintf("Total controls: %d\n\n", s.TotalControls))

	b.WriteString("## Coverage\n\n")
	b.WriteString("| Tier | Count | Percentage |\n")
	b.WriteString("|------|-------|------------|\n")
	b.WriteString(fmt.Sprintf("| Verified (machine-scanned) | %d | %.1f%% |\n", s.Verified, s.VerifiedPct))
	b.WriteString(fmt.Sprintf("| Templated (human-reviewed) | %d | %.1f%% |\n", s.Templated, s.TemplatedPct))
	b.WriteString(fmt.Sprintf("| Manual (human-attested) | %d | %.1f%% |\n", s.Manual, s.ManualPct))

	b.WriteString("\n## By Family\n\n")
	b.WriteString("| Family | Total | Verified | Templated | Manual |\n")
	b.WriteString("|--------|-------|----------|-----------|--------|\n")

	families := []string{"AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PM", "PS", "PT", "RA", "SA", "SC", "SI", "SR"}
	for _, f := range families {
		total := s.ByFamily[f]
		if total == 0 {
			continue
		}
		tiers := s.ByFamilyByTier[f]
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d |\n",
			f, total,
			tiers["verified"], tiers["templated"], tiers["manual"]))
	}

	b.WriteString(fmt.Sprintf("\n---\n\nGenerated by `generate-ssp` on %s\n", s.GeneratedAt))
	return os.WriteFile(path, []byte(b.String()), 0644)
}
