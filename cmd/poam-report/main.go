package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

type SARIFReport struct {
	Runs []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool struct {
		Driver struct {
			Name  string      `json:"name"`
			Rules []SARIFRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
}

type SARIFResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

type POAMItem struct {
	ID            string    `json:"id"`
	Fingerprint   string    `json:"fingerprint"`
	Tool          string    `json:"tool"`
	RuleID        string    `json:"ruleId"`
	Severity      string    `json:"severity"`
	Title         string    `json:"title"`
	Location      string    `json:"location"`
	FirstSeen     time.Time `json:"firstSeen"`
	LastSeen      time.Time `json:"lastSeen"`
	Status        string    `json:"status"`
	NistControls  []string  `json:"nistControls"`
	RemediationDays int     `json:"remediationDays"`
	DueDate       time.Time `json:"dueDate"`
}

type POAMReport struct {
	GeneratedAt time.Time  `json:"generatedAt"`
	ScanDate    string     `json:"scanDate"`
	TotalItems  int        `json:"totalItems"`
	NewItems    int        `json:"newItems"`
	OpenItems   int        `json:"openItems"`
	ClosedItems int        `json:"closedItems"`
	Items       []POAMItem `json:"items"`
	Summary     struct {
		BySeverity map[string]int `json:"bySeverity"`
		ByTool     map[string]int `json:"byTool"`
		ByStatus   map[string]int `json:"byStatus"`
		Overdue    int            `json:"overdue"`
	} `json:"summary"`
}

func main() {
	scanBucket := flag.String("scan-bucket", "", "GCS bucket with SARIF scan results (e.g., archon-fed-ops-staging-build-artifacts)")
	scanPrefix := flag.String("scan-prefix", "security-scans/", "GCS prefix for scan results")
	scanDir := flag.String("scan-dir", "", "Local directory with SARIF files (alternative to GCS)")
	stateFile := flag.String("state-file", "poam-state.json", "Path to POA&M state file for tracking")
	outputDir := flag.String("output-dir", "", "Write reports to this directory")
	jsonOut := flag.Bool("json", false, "JSON output to stdout")
	flag.Parse()

	ctx := context.Background()
	now := time.Now().UTC()

	var sarifFiles []sarifFileContent
	var err error

	if *scanDir != "" {
		sarifFiles, err = loadLocalSARIF(*scanDir)
	} else if *scanBucket != "" {
		sarifFiles, err = loadGCSSARIF(ctx, *scanBucket, *scanPrefix)
	} else {
		log.Fatal("specify --scan-bucket or --scan-dir")
	}
	if err != nil {
		log.Fatalf("load SARIF: %v", err)
	}

	existingState := loadState(*stateFile)

	report := POAMReport{
		GeneratedAt: now,
		ScanDate:    now.Format("2006-01-02"),
	}
	report.Summary.BySeverity = make(map[string]int)
	report.Summary.ByTool = make(map[string]int)
	report.Summary.ByStatus = make(map[string]int)

	currentFingerprints := map[string]bool{}

	for _, sf := range sarifFiles {
		var sarif SARIFReport
		if err := json.Unmarshal(sf.content, &sarif); err != nil {
			log.Printf("WARN: parse %s: %v", sf.name, err)
			continue
		}

		for _, run := range sarif.Runs {
			toolName := run.Tool.Driver.Name
			ruleMap := map[string]SARIFRule{}
			for _, r := range run.Tool.Driver.Rules {
				ruleMap[r.ID] = r
			}

			for _, result := range run.Results {
				severity := normalizeSeverity(result.Level)
				location := ""
				if len(result.Locations) > 0 {
					loc := result.Locations[0]
					location = fmt.Sprintf("%s:%d", loc.PhysicalLocation.ArtifactLocation.URI, loc.PhysicalLocation.Region.StartLine)
				}

				fp := fingerprint(toolName, result.RuleID, location)
				currentFingerprints[fp] = true

				if existing, ok := existingState[fp]; ok {
					existing.LastSeen = now
					existing.Status = "OPEN"
					report.Items = append(report.Items, existing)
					report.OpenItems++
				} else {
					item := POAMItem{
						ID:          fmt.Sprintf("POA-%s", fp[:8]),
						Fingerprint: fp,
						Tool:        toolName,
						RuleID:      result.RuleID,
						Severity:    severity,
						Title:       result.Message.Text,
						Location:    location,
						FirstSeen:   now,
						LastSeen:    now,
						Status:      "NEW",
						NistControls: mapToNIST(toolName, result.RuleID),
						RemediationDays: remediationDays(severity),
					}
					item.DueDate = item.FirstSeen.AddDate(0, 0, item.RemediationDays)
					report.Items = append(report.Items, item)
					report.NewItems++
				}
			}
		}
	}

	for fp, item := range existingState {
		if !currentFingerprints[fp] {
			item.Status = "CLOSED"
			report.Items = append(report.Items, item)
			report.ClosedItems++
		}
	}

	report.TotalItems = len(report.Items)

	for _, item := range report.Items {
		report.Summary.BySeverity[item.Severity]++
		report.Summary.ByTool[item.Tool]++
		report.Summary.ByStatus[item.Status]++
		if item.Status != "CLOSED" && now.After(item.DueDate) {
			report.Summary.Overdue++
		}
	}

	sort.Slice(report.Items, func(i, j int) bool {
		return severityRank(report.Items[i].Severity) > severityRank(report.Items[j].Severity)
	})

	newState := map[string]POAMItem{}
	for _, item := range report.Items {
		if item.Status != "CLOSED" {
			newState[item.Fingerprint] = item
		}
	}
	saveState(*stateFile, newState)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
	} else {
		printMarkdown(os.Stdout, report)
	}

	if *outputDir != "" {
		date := now.Format("2006-01-02")
		writeJSON(filepath.Join(*outputDir, fmt.Sprintf("poam-report-%s.json", date)), report)
		f, err := os.Create(filepath.Join(*outputDir, fmt.Sprintf("poam-report-%s.md", date)))
		if err == nil {
			printMarkdown(f, report)
			f.Close()
		}
	}
}

type sarifFileContent struct {
	name    string
	content []byte
}

func loadLocalSARIF(dir string) ([]sarifFileContent, error) {
	var files []sarifFileContent
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sarif") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			log.Printf("WARN: read %s: %v", e.Name(), err)
			continue
		}
		files = append(files, sarifFileContent{name: e.Name(), content: data})
	}
	return files, nil
}

func loadGCSSARIF(ctx context.Context, bucket, prefix string) ([]sarifFileContent, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage client: %w", err)
	}
	defer client.Close()

	today := time.Now().Format("2006-01-02")
	fullPrefix := prefix + today + "/"

	var files []sarifFileContent
	it := client.Bucket(bucket).Objects(ctx, &storage.Query{Prefix: fullPrefix})
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list objects: %w", err)
		}
		if !strings.HasSuffix(attrs.Name, ".sarif") {
			continue
		}

		reader, err := client.Bucket(bucket).Object(attrs.Name).NewReader(ctx)
		if err != nil {
			log.Printf("WARN: read %s: %v", attrs.Name, err)
			continue
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			log.Printf("WARN: read %s: %v", attrs.Name, err)
			continue
		}
		files = append(files, sarifFileContent{name: attrs.Name, content: data})
	}

	if len(files) == 0 {
		yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		fullPrefix = prefix + yesterday + "/"
		it = client.Bucket(bucket).Objects(ctx, &storage.Query{Prefix: fullPrefix})
		for {
			attrs, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}
			if !strings.HasSuffix(attrs.Name, ".sarif") {
				continue
			}
			reader, err := client.Bucket(bucket).Object(attrs.Name).NewReader(ctx)
			if err != nil {
				continue
			}
			data, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				continue
			}
			files = append(files, sarifFileContent{name: attrs.Name, content: data})
		}
	}

	return files, nil
}

func loadState(path string) map[string]POAMItem {
	state := map[string]POAMItem{}
	data, err := os.ReadFile(path)
	if err != nil {
		return state
	}
	var items []POAMItem
	if err := json.Unmarshal(data, &items); err != nil {
		return state
	}
	for _, item := range items {
		state[item.Fingerprint] = item
	}
	return state
}

func saveState(path string, state map[string]POAMItem) {
	var items []POAMItem
	for _, item := range state {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].FirstSeen.Before(items[j].FirstSeen)
	})
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		log.Printf("WARN: marshal state: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("WARN: write state: %v", err)
	}
}

func fingerprint(tool, ruleID, location string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", tool, ruleID, location)))
	return fmt.Sprintf("%x", h[:16])
}

func normalizeSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "HIGH"
	case "warning":
		return "MEDIUM"
	case "note", "none":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func remediationDays(severity string) int {
	switch severity {
	case "CRITICAL":
		return 15
	case "HIGH":
		return 30
	case "MEDIUM":
		return 90
	case "LOW":
		return 180
	default:
		return 90
	}
}

func mapToNIST(tool, ruleID string) []string {
	switch strings.ToLower(tool) {
	case "gosec", "semgrep":
		return []string{"RA-5", "SA-11"}
	case "trivy":
		if strings.Contains(strings.ToLower(ruleID), "secret") {
			return []string{"IA-5", "SA-11"}
		}
		return []string{"RA-5", "SI-2"}
	case "gitleaks":
		return []string{"IA-5", "SA-11"}
	case "govulncheck":
		return []string{"RA-5", "SI-2"}
	default:
		return []string{"RA-5"}
	}
}

func printMarkdown(w io.Writer, r POAMReport) {
	fmt.Fprintf(w, "# Plan of Action & Milestones (POA&M) Report\n\n")
	fmt.Fprintf(w, "Generated: %s  \n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Scan date: %s  \n\n", r.ScanDate)

	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Count |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| Total items | %d |\n", r.TotalItems)
	fmt.Fprintf(w, "| New | %d |\n", r.NewItems)
	fmt.Fprintf(w, "| Open | %d |\n", r.OpenItems)
	fmt.Fprintf(w, "| Closed | %d |\n", r.ClosedItems)
	fmt.Fprintf(w, "| Overdue | %d |\n\n", r.Summary.Overdue)

	fmt.Fprintf(w, "### By Severity\n\n")
	fmt.Fprintf(w, "| Severity | Count |\n")
	fmt.Fprintf(w, "|----------|-------|\n")
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if c, ok := r.Summary.BySeverity[sev]; ok {
			fmt.Fprintf(w, "| %s | %d |\n", sev, c)
		}
	}

	fmt.Fprintf(w, "\n### By Tool\n\n")
	fmt.Fprintf(w, "| Tool | Count |\n")
	fmt.Fprintf(w, "|------|-------|\n")
	for tool, count := range r.Summary.ByTool {
		fmt.Fprintf(w, "| %s | %d |\n", tool, count)
	}

	if len(r.Items) == 0 {
		fmt.Fprintf(w, "\nNo findings.\n")
		return
	}

	fmt.Fprintf(w, "\n## Items\n\n")
	fmt.Fprintf(w, "| ID | Severity | Tool | Rule | Status | Location | Due Date | Controls |\n")
	fmt.Fprintf(w, "|----|----------|------|------|--------|----------|----------|----------|\n")
	for _, item := range r.Items {
		title := item.Title
		if len(title) > 60 {
			title = title[:57] + "..."
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			item.ID, item.Severity, item.Tool, item.RuleID, item.Status,
			item.Location, item.DueDate.Format("2006-01-02"),
			strings.Join(item.NistControls, ", "))
	}
}

func writeJSON(path string, v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("WARN: marshal: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("WARN: write %s: %v", path, err)
	}
}
