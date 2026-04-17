package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type PolicyStatus struct {
	File         string
	PolicyID     string
	Title        string
	Owner        string
	ReviewCycle  string
	LastModified time.Time
	DaysSince    int
	Overdue      bool
	Controls     []string
}

func main() {
	policiesDir := flag.String("policies-dir", "", "path to policies/ directory (default: auto-detect)")
	maxAgeDays := flag.Int("max-age", 365, "maximum days since last modification before flagging as overdue")
	outputDir := flag.String("output-dir", "", "write report to this directory (default: stdout only)")
	warnOnly := flag.Bool("warn-only", false, "exit 0 even if policies are overdue")
	flag.Parse()

	if *policiesDir == "" {
		*policiesDir = detectPoliciesDir()
	}

	files, err := filepath.Glob(filepath.Join(*policiesDir, "*.md"))
	if err != nil {
		log.Fatalf("glob error: %v", err)
	}
	if len(files) == 0 {
		log.Fatalf("no policy files found in %s", *policiesDir)
	}

	var statuses []PolicyStatus
	var overdue []PolicyStatus

	for _, f := range files {
		status := analyzePolicy(f, *maxAgeDays)
		statuses = append(statuses, status)
		if status.Overdue {
			overdue = append(overdue, status)
		}
	}

	report := formatReport(statuses, overdue, *maxAgeDays)
	fmt.Print(report)

	if *outputDir != "" {
		if err := os.MkdirAll(*outputDir, 0755); err != nil {
			log.Fatalf("mkdir error: %v", err)
		}
		outPath := filepath.Join(*outputDir, fmt.Sprintf("policy-review-%s.md", time.Now().UTC().Format("2006-01-02")))
		if err := os.WriteFile(outPath, []byte(report), 0644); err != nil {
			log.Fatalf("write error: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wrote report to %s\n", outPath)
	}

	if len(overdue) > 0 && !*warnOnly {
		fmt.Fprintf(os.Stderr, "\n%d policies overdue for review\n", len(overdue))
		os.Exit(1)
	}
}

func analyzePolicy(path string, maxAgeDays int) PolicyStatus {
	status := PolicyStatus{
		File: filepath.Base(path),
	}

	parseFrontmatter(path, &status)

	lastMod := gitLastModified(path)
	if lastMod.IsZero() {
		info, err := os.Stat(path)
		if err == nil {
			lastMod = info.ModTime()
		}
	}

	status.LastModified = lastMod
	status.DaysSince = int(time.Since(lastMod).Hours() / 24)
	status.Overdue = status.DaysSince > maxAgeDays

	return status
}

func gitLastModified(path string) time.Time {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return time.Time{}
	}

	cmd := exec.Command("git", "log", "-1", "--format=%aI", "--", absPath)
	cmd.Dir = filepath.Dir(absPath)
	out, err := cmd.Output()
	if err != nil {
		return time.Time{}
	}

	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(out)))
	if err != nil {
		return time.Time{}
	}
	return t
}

var (
	policyIDRe = regexp.MustCompile(`(?i)\*\*Policy ID\*\*\s*[:：]?\s*(.+)`)
	ownerRe    = regexp.MustCompile(`(?i)\*\*Owner\*\*\s*[:：]?\s*(.+)`)
	reviewRe   = regexp.MustCompile(`(?i)\*\*Review Cycle\*\*\s*[:：]?\s*(.+)`)
	controlsRe = regexp.MustCompile(`(?i)\*\*NIST 800-53 Controls?\*\*\s*[:：]?\s*(.+)`)
	titleRe    = regexp.MustCompile(`^#\s+(.+)`)
)

func parseFrontmatter(path string, status *PolicyStatus) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lines := 0
	for scanner.Scan() && lines < 20 {
		line := scanner.Text()
		lines++

		if m := titleRe.FindStringSubmatch(line); m != nil && status.Title == "" {
			status.Title = strings.TrimSpace(m[1])
		}
		if m := policyIDRe.FindStringSubmatch(line); m != nil {
			status.PolicyID = strings.TrimSpace(m[1])
		}
		if m := ownerRe.FindStringSubmatch(line); m != nil {
			status.Owner = strings.TrimSpace(m[1])
		}
		if m := reviewRe.FindStringSubmatch(line); m != nil {
			status.ReviewCycle = strings.TrimSpace(m[1])
		}
		if m := controlsRe.FindStringSubmatch(line); m != nil {
			for _, c := range strings.Split(m[1], ",") {
				status.Controls = append(status.Controls, strings.TrimSpace(c))
			}
		}
	}
}

func formatReport(all []PolicyStatus, overdue []PolicyStatus, maxAge int) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# Policy Review Report — %s\n\n", time.Now().UTC().Format("2006-01-02")))
	b.WriteString(fmt.Sprintf("Review threshold: %d days\n\n", maxAge))

	if len(overdue) == 0 {
		b.WriteString("**All policies are current.** No reviews required.\n\n")
	} else {
		b.WriteString(fmt.Sprintf("**%d of %d policies require review:**\n\n", len(overdue), len(all)))
		for _, p := range overdue {
			b.WriteString(fmt.Sprintf("- **%s** (%s): last modified %s (%d days ago)\n",
				p.File, p.PolicyID, p.LastModified.Format("2006-01-02"), p.DaysSince))
			if len(p.Controls) > 0 {
				b.WriteString(fmt.Sprintf("  Controls: %s\n", strings.Join(p.Controls, ", ")))
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("## All Policies\n\n")
	b.WriteString("| Policy | ID | Owner | Review Cycle | Last Modified | Days | Status |\n")
	b.WriteString("|--------|----|-------|--------------|---------------|------|--------|\n")

	for _, p := range all {
		st := "Current"
		if p.Overdue {
			st = "OVERDUE"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %d | %s |\n",
			p.File, p.PolicyID, p.Owner, p.ReviewCycle,
			p.LastModified.Format("2006-01-02"), p.DaysSince, st))
	}

	b.WriteString(fmt.Sprintf("\n---\n\nGenerated by `policy-review` on %s\n", time.Now().UTC().Format(time.RFC3339)))
	return b.String()
}

func detectPoliciesDir() string {
	dir, _ := os.Getwd()
	for {
		candidate := filepath.Join(dir, "compliance", "policies")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		candidate = filepath.Join(dir, "policies")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "policies"
}
