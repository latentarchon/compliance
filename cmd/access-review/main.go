package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type ProjectConfig struct {
	AdminProject string
	AppProject   string
	Region       string
}

func envConfig(env string) ProjectConfig {
	if env == "production" {
		return ProjectConfig{
			AdminProject: "archon-fed-admin",
			AppProject:   "archon-fed-app",
			Region:       "us-east4",
		}
	}
	return ProjectConfig{
		AdminProject: "archon-admin-staging",
		AppProject:   "archon-app-staging",
		Region:       "us-east4",
	}
}

type TenantUser struct {
	LocalID       string    `json:"localId"`
	Email         string    `json:"email"`
	DisplayName   string    `json:"displayName,omitempty"`
	Disabled      bool      `json:"disabled"`
	LastLoginAt   time.Time `json:"lastLoginAt"`
	CreatedAt     time.Time `json:"createdAt"`
	TenantID      string    `json:"tenantId"`
	Project       string    `json:"project"`
	InactiveDays  int       `json:"inactiveDays"`
	NeverLoggedIn bool      `json:"neverLoggedIn"`
}

type ReviewReport struct {
	GeneratedAt     time.Time    `json:"generatedAt"`
	Environment     string       `json:"environment"`
	MaxInactiveDays int          `json:"maxInactiveDays"`
	TotalUsers      int          `json:"totalUsers"`
	ActiveUsers     int          `json:"activeUsers"`
	InactiveUsers   int          `json:"inactiveUsers"`
	DisabledUsers   int          `json:"disabledUsers"`
	NeverLoggedIn   int          `json:"neverLoggedIn"`
	Findings        []TenantUser `json:"findings"`
	DisableActions  []string     `json:"disableActions,omitempty"`
}

func main() {
	env := flag.String("env", "staging", "Environment: staging or production")
	maxInactive := flag.Int("max-inactive-days", 90, "Days of inactivity before flagging")
	disable := flag.Bool("disable", false, "Actually disable inactive accounts (default: dry-run)")
	outputDir := flag.String("output-dir", "", "Write reports to this directory")
	jsonOut := flag.Bool("json", false, "JSON output to stdout")
	warnOnly := flag.Bool("warn-only", false, "Exit 0 even if inactive accounts found")
	flag.Parse()

	ctx := context.Background()
	cfg := envConfig(*env)

	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		log.Fatalf("credentials: %v", err)
	}
	client := oauth2.NewClient(ctx, creds.TokenSource)

	report := ReviewReport{
		GeneratedAt:     time.Now().UTC(),
		Environment:     *env,
		MaxInactiveDays: *maxInactive,
	}

	now := time.Now().UTC()
	threshold := now.AddDate(0, 0, -*maxInactive)

	for _, project := range []string{cfg.AdminProject, cfg.AppProject} {
		tenants, err := listTenants(ctx, client, project)
		if err != nil {
			log.Printf("WARN: cannot list tenants for %s: %v", project, err)
			continue
		}

		for _, tenantID := range tenants {
			users, err := listTenantUsers(ctx, client, project, tenantID)
			if err != nil {
				log.Printf("WARN: cannot list users for %s/%s: %v", project, tenantID, err)
				continue
			}

			for _, u := range users {
				report.TotalUsers++
				u.TenantID = tenantID
				u.Project = project

				if u.Disabled {
					report.DisabledUsers++
					continue
				}

				if u.LastLoginAt.IsZero() {
					u.NeverLoggedIn = true
					u.InactiveDays = int(now.Sub(u.CreatedAt).Hours() / 24)
					report.NeverLoggedIn++
					if u.CreatedAt.Before(threshold) {
						report.InactiveUsers++
						report.Findings = append(report.Findings, u)
					} else {
						report.ActiveUsers++
					}
					continue
				}

				u.InactiveDays = int(now.Sub(u.LastLoginAt).Hours() / 24)
				if u.LastLoginAt.Before(threshold) {
					report.InactiveUsers++
					report.Findings = append(report.Findings, u)
				} else {
					report.ActiveUsers++
				}
			}
		}
	}

	if *disable && len(report.Findings) > 0 {
		for _, f := range report.Findings {
			err := disableUser(ctx, client, f.Project, f.TenantID, f.LocalID)
			if err != nil {
				log.Printf("ERROR: disable %s (%s): %v", f.Email, f.LocalID, err)
				report.DisableActions = append(report.DisableActions, fmt.Sprintf("FAILED: %s — %v", f.Email, err))
			} else {
				log.Printf("DISABLED: %s (%s) — inactive %d days", f.Email, f.LocalID, f.InactiveDays)
				report.DisableActions = append(report.DisableActions, fmt.Sprintf("DISABLED: %s — inactive %d days", f.Email, f.InactiveDays))
			}
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
	} else {
		printMarkdown(os.Stdout, report, *disable)
	}

	if *outputDir != "" {
		date := time.Now().Format("2006-01-02")
		writeJSON(filepath.Join(*outputDir, fmt.Sprintf("access-review-%s.json", date)), report)
		f, err := os.Create(filepath.Join(*outputDir, fmt.Sprintf("access-review-%s.md", date)))
		if err == nil {
			printMarkdown(f, report, *disable)
			f.Close()
		}
	}

	if len(report.Findings) > 0 && !*warnOnly {
		os.Exit(1)
	}
}

func listTenants(ctx context.Context, client *http.Client, project string) ([]string, error) {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v2/projects/%s/tenants?pageSize=100", project)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var result struct {
		Tenants []struct {
			Name string `json:"name"`
		} `json:"tenants"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var ids []string
	for _, t := range result.Tenants {
		parts := strings.Split(t.Name, "/")
		ids = append(ids, parts[len(parts)-1])
	}
	return ids, nil
}

func listTenantUsers(ctx context.Context, client *http.Client, project, tenantID string) ([]TenantUser, error) {
	var allUsers []TenantUser
	nextPage := ""

	for {
		url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/projects/%s/tenants/%s/accounts:batchGet?maxResults=500", project, tenantID)
		if nextPage != "" {
			url += "&nextPageToken=" + nextPage
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
		}

		var result struct {
			Users []struct {
				LocalID     string `json:"localId"`
				Email       string `json:"email"`
				DisplayName string `json:"displayName"`
				Disabled    bool   `json:"disabled"`
				LastLoginAt string `json:"lastLoginAt"`
				CreatedAt   string `json:"createdAt"`
			} `json:"users"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, err
		}

		for _, u := range result.Users {
			tu := TenantUser{
				LocalID:     u.LocalID,
				Email:       u.Email,
				DisplayName: u.DisplayName,
				Disabled:    u.Disabled,
				LastLoginAt: parseEpochMs(u.LastLoginAt),
				CreatedAt:   parseEpochMs(u.CreatedAt),
			}
			allUsers = append(allUsers, tu)
		}

		if result.NextPageToken == "" {
			break
		}
		nextPage = result.NextPageToken
	}

	return allUsers, nil
}

func disableUser(ctx context.Context, client *http.Client, project, tenantID, userID string) error {
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/projects/%s/tenants/%s/accounts:update", project, tenantID)
	payload := fmt.Sprintf(`{"localId":"%s","disableUser":true}`, userID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return nil
}

func parseEpochMs(s string) time.Time {
	if s == "" || s == "0" {
		return time.Time{}
	}
	var ms int64
	fmt.Sscanf(s, "%d", &ms)
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

func printMarkdown(w io.Writer, r ReviewReport, disabled bool) {
	fmt.Fprintf(w, "# Access Review Report\n\n")
	fmt.Fprintf(w, "Generated: %s  \n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Environment: %s  \n", r.Environment)
	fmt.Fprintf(w, "Inactivity threshold: %d days  \n\n", r.MaxInactiveDays)

	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Count |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| Total users | %d |\n", r.TotalUsers)
	fmt.Fprintf(w, "| Active | %d |\n", r.ActiveUsers)
	fmt.Fprintf(w, "| Inactive (>%d days) | %d |\n", r.MaxInactiveDays, r.InactiveUsers)
	fmt.Fprintf(w, "| Already disabled | %d |\n", r.DisabledUsers)
	fmt.Fprintf(w, "| Never logged in | %d |\n\n", r.NeverLoggedIn)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "No inactive accounts found.\n")
		return
	}

	fmt.Fprintf(w, "## Inactive Accounts\n\n")
	fmt.Fprintf(w, "| Email | Tenant | Project | Last Login | Inactive Days | Never Logged In |\n")
	fmt.Fprintf(w, "|-------|--------|---------|------------|---------------|-----------------|\n")
	for _, f := range r.Findings {
		lastLogin := f.LastLoginAt.Format("2006-01-02")
		if f.NeverLoggedIn {
			lastLogin = "never"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %d | %v |\n",
			f.Email, f.TenantID, f.Project, lastLogin, f.InactiveDays, f.NeverLoggedIn)
	}

	if disabled && len(r.DisableActions) > 0 {
		fmt.Fprintf(w, "\n## Disable Actions\n\n")
		for _, a := range r.DisableActions {
			fmt.Fprintf(w, "- %s\n", a)
		}
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
