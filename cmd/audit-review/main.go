package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
)

type ProjectConfig struct {
	AdminProject string
	OpsProject   string
	AppProject   string
}

func envConfig(env string) ProjectConfig {
	if env == "production" {
		return ProjectConfig{
			AdminProject: "archon-fed-admin-prod",
			OpsProject:   "archon-fed-ops-prod",
			AppProject:   "archon-fed-app-prod",
		}
	}
	return ProjectConfig{
		AdminProject: "archon-admin-staging",
		OpsProject:   "archon-ops-staging",
		AppProject:   "archon-app-staging",
	}
}

type AnomalyFinding struct {
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Project   string `json:"project"`
	Details   string `json:"details"`
	Count     int64  `json:"count"`
	TimeRange string `json:"timeRange"`
}

type AuditReport struct {
	GeneratedAt time.Time         `json:"generatedAt"`
	Environment string            `json:"environment"`
	ReviewDays  int               `json:"reviewDays"`
	Findings    []AnomalyFinding  `json:"findings"`
	Queries     map[string]string `json:"queries"`
	Summary     ReportSummary     `json:"summary"`
}

type ReportSummary struct {
	TotalFindings    int            `json:"totalFindings"`
	BySeverity       map[string]int `json:"bySeverity"`
	CategoriesWithHits []string     `json:"categoriesWithHits"`
}

func main() {
	env := flag.String("env", "staging", "Environment: staging or production")
	days := flag.Int("days", 7, "Review period in days")
	outputDir := flag.String("output-dir", "", "Write reports to this directory")
	jsonOut := flag.Bool("json", false, "JSON output to stdout")
	warnOnly := flag.Bool("warn-only", false, "Exit 0 even if anomalies found")
	flag.Parse()

	ctx := context.Background()
	cfg := envConfig(*env)

	report := AuditReport{
		GeneratedAt: time.Now().UTC(),
		Environment: *env,
		ReviewDays:  *days,
		Queries:     make(map[string]string),
		Summary: ReportSummary{
			BySeverity: make(map[string]int),
		},
	}

	startTime := time.Now().UTC().AddDate(0, 0, -*days).Format("2006-01-02")
	endTime := time.Now().UTC().Format("2006-01-02")
	timeRange := fmt.Sprintf("%s to %s", startTime, endTime)

	for _, project := range []string{cfg.AdminProject, cfg.OpsProject, cfg.AppProject} {
		client, err := bigquery.NewClient(ctx, project)
		if err != nil {
			log.Printf("WARN: bigquery client for %s: %v", project, err)
			continue
		}
		defer client.Close()

		runAuditQueries(ctx, client, project, startTime, endTime, timeRange, &report)
	}

	seen := map[string]bool{}
	for _, f := range report.Findings {
		report.Summary.TotalFindings++
		report.Summary.BySeverity[f.Severity]++
		if !seen[f.Category] {
			seen[f.Category] = true
			report.Summary.CategoriesWithHits = append(report.Summary.CategoriesWithHits, f.Category)
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
	} else {
		printMarkdown(os.Stdout, report)
	}

	if *outputDir != "" {
		date := time.Now().Format("2006-01-02")
		writeJSON(filepath.Join(*outputDir, fmt.Sprintf("audit-review-%s.json", date)), report)
		f, err := os.Create(filepath.Join(*outputDir, fmt.Sprintf("audit-review-%s.md", date)))
		if err == nil {
			printMarkdown(f, report)
			f.Close()
		}
	}

	high := report.Summary.BySeverity["HIGH"] + report.Summary.BySeverity["CRITICAL"]
	if high > 0 && !*warnOnly {
		os.Exit(1)
	}
}

type queryDef struct {
	Name     string
	Category string
	Severity string
	Query    string
}

func auditQueries(project, startTime, endTime string) []queryDef {
	dataset := fmt.Sprintf("`%s.audit_logs`", project)
	return []queryDef{
		{
			Name:     "failed_auth_spikes",
			Category: "Authentication Failures",
			Severity: "HIGH",
			Query: fmt.Sprintf(`SELECT
  COUNT(*) as event_count,
  TIMESTAMP_TRUNC(timestamp, HOUR) as hour,
  protopayload_auditlog.authenticationInfo.principalEmail as principal
FROM %s.cloudaudit_googleapis_com_activity
WHERE timestamp >= '%s' AND timestamp < '%s'
  AND protopayload_auditlog.status.code != 0
GROUP BY hour, principal
HAVING event_count > 10
ORDER BY event_count DESC
LIMIT 50`, dataset, startTime, endTime),
		},
		{
			Name:     "iam_changes",
			Category: "IAM Policy Changes",
			Severity: "MEDIUM",
			Query: fmt.Sprintf(`SELECT
  COUNT(*) as event_count,
  protopayload_auditlog.methodName as method,
  protopayload_auditlog.authenticationInfo.principalEmail as principal,
  protopayload_auditlog.resourceName as resource
FROM %s.cloudaudit_googleapis_com_activity
WHERE timestamp >= '%s' AND timestamp < '%s'
  AND protopayload_auditlog.methodName LIKE '%%SetIamPolicy%%'
GROUP BY method, principal, resource
ORDER BY event_count DESC
LIMIT 50`, dataset, startTime, endTime),
		},
		{
			Name:     "privilege_escalation",
			Category: "Privilege Escalation Attempts",
			Severity: "CRITICAL",
			Query: fmt.Sprintf(`SELECT
  COUNT(*) as event_count,
  protopayload_auditlog.methodName as method,
  protopayload_auditlog.authenticationInfo.principalEmail as principal
FROM %s.cloudaudit_googleapis_com_activity
WHERE timestamp >= '%s' AND timestamp < '%s'
  AND (protopayload_auditlog.methodName LIKE '%%CreateRole%%'
    OR protopayload_auditlog.methodName LIKE '%%UpdateRole%%'
    OR protopayload_auditlog.methodName LIKE '%%CreateServiceAccountKey%%')
GROUP BY method, principal
ORDER BY event_count DESC
LIMIT 50`, dataset, startTime, endTime),
		},
		{
			Name:     "data_deletion",
			Category: "Data Deletion Events",
			Severity: "HIGH",
			Query: fmt.Sprintf(`SELECT
  COUNT(*) as event_count,
  protopayload_auditlog.methodName as method,
  protopayload_auditlog.authenticationInfo.principalEmail as principal,
  protopayload_auditlog.resourceName as resource
FROM %s.cloudaudit_googleapis_com_activity
WHERE timestamp >= '%s' AND timestamp < '%s'
  AND (protopayload_auditlog.methodName LIKE '%%delete%%'
    OR protopayload_auditlog.methodName LIKE '%%Delete%%'
    OR protopayload_auditlog.methodName LIKE '%%Remove%%')
GROUP BY method, principal, resource
HAVING event_count > 5
ORDER BY event_count DESC
LIMIT 50`, dataset, startTime, endTime),
		},
		{
			Name:     "off_hours_access",
			Category: "Off-Hours Administrative Access",
			Severity: "MEDIUM",
			Query: fmt.Sprintf(`SELECT
  COUNT(*) as event_count,
  protopayload_auditlog.authenticationInfo.principalEmail as principal,
  EXTRACT(HOUR FROM timestamp AT TIME ZONE 'America/New_York') as hour_et
FROM %s.cloudaudit_googleapis_com_activity
WHERE timestamp >= '%s' AND timestamp < '%s'
  AND EXTRACT(HOUR FROM timestamp AT TIME ZONE 'America/New_York') NOT BETWEEN 7 AND 19
  AND protopayload_auditlog.authenticationInfo.principalEmail IS NOT NULL
  AND protopayload_auditlog.authenticationInfo.principalEmail NOT LIKE '%%gserviceaccount.com'
GROUP BY principal, hour_et
HAVING event_count > 3
ORDER BY event_count DESC
LIMIT 50`, dataset, startTime, endTime),
		},
		{
			Name:     "app_auth_failures",
			Category: "Application Auth Failures",
			Severity: "HIGH",
			Query: fmt.Sprintf(`SELECT
  COUNT(*) as event_count,
  TIMESTAMP_TRUNC(timestamp, HOUR) as hour,
  jsonPayload.action as action
FROM %s.run_googleapis_com_stderr
WHERE timestamp >= '%s' AND timestamp < '%s'
  AND jsonPayload.level = 'AUDIT_EVENT'
  AND jsonPayload.action LIKE '%%fail%%'
GROUP BY hour, action
HAVING event_count > 20
ORDER BY event_count DESC
LIMIT 50`, dataset, startTime, endTime),
		},
	}
}

func runAuditQueries(ctx context.Context, client *bigquery.Client, project, startTime, endTime, timeRange string, report *AuditReport) {
	queries := auditQueries(project, startTime, endTime)

	for _, qd := range queries {
		report.Queries[qd.Name] = qd.Query

		q := client.Query(qd.Query)
		q.DefaultProjectID = project

		it, err := q.Read(ctx)
		if err != nil {
			log.Printf("WARN: query %s on %s: %v", qd.Name, project, err)
			continue
		}

		rowCount := int64(0)
		for {
			var row map[string]bigquery.Value
			err := it.Next(&row)
			if err == iterator.Done {
				break
			}
			if err != nil {
				log.Printf("WARN: read %s on %s: %v", qd.Name, project, err)
				break
			}
			rowCount++

			count := int64(0)
			if v, ok := row["event_count"]; ok {
				if c, ok := v.(int64); ok {
					count = c
				}
			}

			details := formatRow(row)
			report.Findings = append(report.Findings, AnomalyFinding{
				Category:  qd.Category,
				Severity:  qd.Severity,
				Project:   project,
				Details:   details,
				Count:     count,
				TimeRange: timeRange,
			})
		}

		if rowCount == 0 {
			log.Printf("  %s/%s: no anomalies", project, qd.Name)
		} else {
			log.Printf("  %s/%s: %d anomalies", project, qd.Name, rowCount)
		}
	}
}

func formatRow(row map[string]bigquery.Value) string {
	parts := []string{}
	for k, v := range row {
		if k == "event_count" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return fmt.Sprintf("{%s}", joinStrings(parts, ", "))
}

func joinStrings(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}

func printMarkdown(w io.Writer, r AuditReport) {
	fmt.Fprintf(w, "# Audit Log Review Report\n\n")
	fmt.Fprintf(w, "Generated: %s  \n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Environment: %s  \n", r.Environment)
	fmt.Fprintf(w, "Review period: %d days  \n\n", r.ReviewDays)

	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Count |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| Total anomalies | %d |\n", r.Summary.TotalFindings)
	for sev, count := range r.Summary.BySeverity {
		fmt.Fprintf(w, "| %s | %d |\n", sev, count)
	}
	fmt.Fprintf(w, "\n")

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "No anomalies detected during review period.\n")
		return
	}

	fmt.Fprintf(w, "## Findings\n\n")

	categories := map[string][]AnomalyFinding{}
	for _, f := range r.Findings {
		categories[f.Category] = append(categories[f.Category], f)
	}

	for cat, findings := range categories {
		fmt.Fprintf(w, "### %s\n\n", cat)
		fmt.Fprintf(w, "| Severity | Project | Count | Details |\n")
		fmt.Fprintf(w, "|----------|---------|-------|---------|\n")
		for _, f := range findings {
			fmt.Fprintf(w, "| %s | %s | %d | %s |\n", f.Severity, f.Project, f.Count, f.Details)
		}
		fmt.Fprintf(w, "\n")
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
