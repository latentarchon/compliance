// Package client provides a Go client for the Drata Public API V2.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultBaseURL = "https://public-api.drata.com/public/v2"
	defaultTimeout = 30 * time.Second
	// Drata rate limit: 100 requests per minute
	rateLimit    = 100
	rateBurst    = 10
	userAgent    = "latentarchon-drata-sync/1.0"
)

// Client is a Drata API V2 client.
type Client struct {
	baseURL     string
	apiKey      string
	httpClient  *http.Client
	limiter     *rate.Limiter
	workspaceID string // Drata workspace ID (required for most endpoints)
}

// Option configures the Client.
type Option func(*Client)

// WithBaseURL overrides the default API base URL.
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

// WithWorkspaceID sets the Drata workspace ID.
func WithWorkspaceID(id string) Option {
	return func(c *Client) { c.workspaceID = id }
}

// New creates a new Drata API client. apiKey is required.
func New(apiKey string, opts ...Option) *Client {
	c := &Client{
		baseURL: defaultBaseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		limiter: rate.NewLimiter(rate.Every(time.Minute/rateLimit), rateBurst),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// NewFromEnv creates a client from environment variables.
// DRATA_API_KEY (required), DRATA_WORKSPACE_ID (required), DRATA_BASE_URL (optional).
func NewFromEnv() (*Client, error) {
	key := os.Getenv("DRATA_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("DRATA_API_KEY environment variable is required")
	}
	wsID := os.Getenv("DRATA_WORKSPACE_ID")
	if wsID == "" {
		return nil, fmt.Errorf("DRATA_WORKSPACE_ID environment variable is required")
	}
	opts := []Option{WithWorkspaceID(wsID)}
	if u := os.Getenv("DRATA_BASE_URL"); u != "" {
		opts = append(opts, WithBaseURL(u))
	}
	return New(key, opts...), nil
}

// Pagination holds cursor-based pagination state.
type Pagination struct {
	Cursor     string `json:"cursor,omitempty"`
	TotalCount int    `json:"totalCount,omitempty"`
}

// APIError is returned when the API responds with a non-2xx status.
type APIError struct {
	StatusCode int
	Body       string
	Endpoint   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("drata API %s returned %d: %s", e.Endpoint, e.StatusCode, e.Body)
}

// do executes an HTTP request with rate limiting and auth.
func (c *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", userAgent)
	return c.httpClient.Do(req.WithContext(ctx))
}

// get performs a GET request and decodes the JSON response into dst.
func (c *Client) get(ctx context.Context, path string, query url.Values, dst interface{}) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Body: string(body), Endpoint: "GET " + path}
	}
	if dst != nil {
		return json.NewDecoder(resp.Body).Decode(dst)
	}
	return nil
}

// post performs a POST request with a JSON body and decodes the response.
func (c *Client) post(ctx context.Context, path string, body, dst interface{}) error {
	return c.jsonRequest(ctx, "POST", path, body, dst)
}

// put performs a PUT request with a JSON body and decodes the response.
func (c *Client) put(ctx context.Context, path string, body, dst interface{}) error {
	return c.jsonRequest(ctx, "PUT", path, body, dst)
}

// patch performs a PATCH request with a JSON body and decodes the response.
func (c *Client) patch(ctx context.Context, path string, body, dst interface{}) error {
	return c.jsonRequest(ctx, "PATCH", path, body, dst)
}

// del performs a DELETE request.
func (c *Client) del(ctx context.Context, path string) error {
	req, err := http.NewRequest("DELETE", c.baseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Body: string(body), Endpoint: "DELETE " + path}
	}
	return nil
}

func (c *Client) jsonRequest(ctx context.Context, method, path string, body, dst interface{}) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return fmt.Errorf("encode body: %w", err)
		}
	}
	req, err := http.NewRequest(method, c.baseURL+path, &buf)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Body: string(b), Endpoint: method + " " + path}
	}
	if dst != nil {
		return json.NewDecoder(resp.Body).Decode(dst)
	}
	return nil
}

// postMultipart performs a multipart/form-data POST and decodes the response.
func (c *Client) postMultipart(ctx context.Context, path string, fields map[string]string, files map[string]string, dst interface{}) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return fmt.Errorf("write field %s: %w", k, err)
		}
	}
	for fieldName, filePath := range files {
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("open file %s: %w", filePath, err)
		}
		part, err := w.CreateFormFile(fieldName, filepath.Base(filePath))
		if err != nil {
			f.Close()
			return fmt.Errorf("create form file: %w", err)
		}
		if _, err := io.Copy(part, f); err != nil {
			f.Close()
			return fmt.Errorf("copy file: %w", err)
		}
		f.Close()
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close multipart writer: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Body: string(b), Endpoint: "POST " + path}
	}
	if dst != nil {
		return json.NewDecoder(resp.Body).Decode(dst)
	}
	return nil
}

// wsPath returns a workspace-prefixed path.
func (c *Client) wsPath(path string) string {
	return fmt.Sprintf("/workspaces/%s%s", c.workspaceID, path)
}

// --- Controls ---

// Control represents a Drata control.
type Control struct {
	ID                string        `json:"id"`
	Name              string        `json:"name"`
	Code              string        `json:"code"`
	Slug              string        `json:"slug"`
	Description       string        `json:"description"`
	Question          string        `json:"question"`
	Activity          string        `json:"activity"`
	FrameworkTags     []string      `json:"frameworkTags"`
	ControlTemplateID string        `json:"controlTemplateId"`
	Flags             ControlFlags  `json:"flags"`
	CreatedAt         string        `json:"createdAt"`
	UpdatedAt         string        `json:"updatedAt"`
}

type ControlFlags struct {
	HasEvidence bool `json:"hasEvidence"`
	HasPolicy   bool `json:"hasPolicy"`
	IsReady     bool `json:"isReady"`
	HasTicket   bool `json:"hasTicket"`
	HasOwner    bool `json:"hasOwner"`
	IsMonitored bool `json:"isMonitored"`
}

type ControlListResponse struct {
	Data       []Control  `json:"data"`
	Pagination Pagination `json:"pagination"`
}

// ListControls returns all controls, paginating automatically.
func (c *Client) ListControls(ctx context.Context) ([]Control, error) {
	var all []Control
	var cursor string
	for {
		q := url.Values{"limit": {"100"}, "includeCount": {"true"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp ControlListResponse
		if err := c.get(ctx, c.wsPath("/controls"), q, &resp); err != nil {
			return nil, fmt.Errorf("list controls: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Pagination.Cursor == "" {
			break
		}
		cursor = resp.Pagination.Cursor
	}
	return all, nil
}

// CreateControl creates a custom control.
type CreateControlRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Question       string   `json:"question,omitempty"`
	Code           string   `json:"code,omitempty"`
	Activity       string   `json:"activity,omitempty"`
	PolicyIDs      []string `json:"policyIds,omitempty"`
	RequirementIDs []string `json:"requirementIds,omitempty"`
	OwnerIDs       []int    `json:"ownerIds,omitempty"`
}

func (c *Client) CreateControl(ctx context.Context, req CreateControlRequest) (*Control, error) {
	var ctrl Control
	if err := c.post(ctx, c.wsPath("/controls"), req, &ctrl); err != nil {
		return nil, fmt.Errorf("create control: %w", err)
	}
	return &ctrl, nil
}

// --- Evidence Library ---

// EvidenceItem represents a Drata evidence library item.
type EvidenceItem struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type EvidenceListResponse struct {
	Data       []EvidenceItem `json:"data"`
	Pagination Pagination     `json:"pagination"`
}

// ListEvidence returns all evidence library items.
func (c *Client) ListEvidence(ctx context.Context) ([]EvidenceItem, error) {
	var all []EvidenceItem
	var cursor string
	for {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp EvidenceListResponse
		if err := c.get(ctx, c.wsPath("/evidence-library"), q, &resp); err != nil {
			return nil, fmt.Errorf("list evidence: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Pagination.Cursor == "" {
			break
		}
		cursor = resp.Pagination.Cursor
	}
	return all, nil
}

// CreateEvidence uploads a file as evidence linked to controls.
func (c *Client) CreateEvidence(ctx context.Context, name, description string, controlIDs []string, filePath string, ownerID int) (*EvidenceItem, error) {
	fields := map[string]string{
		"name":                name,
		"renewalScheduleType": "ONE_YEAR",
		"filedAt":             time.Now().UTC().Format(time.RFC3339),
		"ownerId":             strconv.Itoa(ownerID),
	}
	if description != "" {
		fields["description"] = description
	}
	for i, cid := range controlIDs {
		fields[fmt.Sprintf("controlIds[%d]", i)] = cid
	}

	var item EvidenceItem
	if err := c.postMultipart(ctx, c.wsPath("/evidence-library"), fields, map[string]string{"file": filePath}, &item); err != nil {
		return nil, fmt.Errorf("create evidence: %w", err)
	}
	return &item, nil
}

// CreateEvidenceFromURL creates evidence from a URL instead of a file.
func (c *Client) CreateEvidenceFromURL(ctx context.Context, name, description, evidenceURL string, controlIDs []string, ownerID int) (*EvidenceItem, error) {
	fields := map[string]string{
		"name":                name,
		"url":                 evidenceURL,
		"renewalScheduleType": "ONE_YEAR",
		"filedAt":             time.Now().UTC().Format(time.RFC3339),
		"ownerId":             strconv.Itoa(ownerID),
	}
	if description != "" {
		fields["description"] = description
	}
	for i, cid := range controlIDs {
		fields[fmt.Sprintf("controlIds[%d]", i)] = cid
	}

	var item EvidenceItem
	if err := c.postMultipart(ctx, c.wsPath("/evidence-library"), fields, nil, &item); err != nil {
		return nil, fmt.Errorf("create evidence from URL: %w", err)
	}
	return &item, nil
}

// --- Personnel ---

// Personnel represents a Drata personnel record.
type Personnel struct {
	ID               int              `json:"id"`
	UserID           int              `json:"userId"`
	User             PersonnelUser    `json:"user"`
	EmploymentStatus string           `json:"employmentStatus"`
	ComplianceChecks []ComplianceCheck `json:"complianceChecks"`
	StartedAt        string           `json:"startedAt"`
	SeparatedAt      string           `json:"separatedAt,omitempty"`
	CreatedAt        string           `json:"createdAt"`
	UpdatedAt        string           `json:"updatedAt"`
}

type PersonnelUser struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type ComplianceCheck struct {
	ID             int    `json:"id"`
	Type           string `json:"type"`
	Status         string `json:"status"`
	CheckFrequency string `json:"checkFrequency"`
	ExpiresAt      string `json:"expiresAt,omitempty"`
	LastCheckedAt  string `json:"lastCheckedAt,omitempty"`
	CompletionDate string `json:"completionDate,omitempty"`
}

type PersonnelListResponse struct {
	Data       []Personnel `json:"data"`
	Pagination Pagination  `json:"pagination"`
}

// ListPersonnel returns all personnel records with compliance checks expanded.
func (c *Client) ListPersonnel(ctx context.Context) ([]Personnel, error) {
	var all []Personnel
	var cursor string
	for {
		q := url.Values{"limit": {"100"}, "expand[]": {"complianceChecks"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp PersonnelListResponse
		if err := c.get(ctx, "/personnel", q, &resp); err != nil {
			return nil, fmt.Errorf("list personnel: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Pagination.Cursor == "" {
			break
		}
		cursor = resp.Pagination.Cursor
	}
	return all, nil
}

// UpdatePersonnel updates a personnel record.
type UpdatePersonnelRequest struct {
	EmploymentStatus string `json:"employmentStatus,omitempty"`
}

func (c *Client) UpdatePersonnel(ctx context.Context, id int, req UpdatePersonnelRequest) (*Personnel, error) {
	var p Personnel
	if err := c.patch(ctx, fmt.Sprintf("/personnel/%d", id), req, &p); err != nil {
		return nil, fmt.Errorf("update personnel: %w", err)
	}
	return &p, nil
}

// --- Background Checks ---

// BackgroundCheck represents a background check record.
type BackgroundCheck struct {
	ID             int    `json:"id"`
	PersonnelID    int    `json:"personnelId"`
	CompletionDate string `json:"completionDate"`
	CreatedAt      string `json:"createdAt"`
}

type BackgroundCheckListResponse struct {
	Data       []BackgroundCheck `json:"data"`
	Pagination Pagination        `json:"pagination"`
}

// ListBackgroundChecks returns background check records.
func (c *Client) ListBackgroundChecks(ctx context.Context) ([]BackgroundCheck, error) {
	var all []BackgroundCheck
	var cursor string
	for {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp BackgroundCheckListResponse
		if err := c.get(ctx, "/background-checks", q, &resp); err != nil {
			return nil, fmt.Errorf("list background checks: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Pagination.Cursor == "" {
			break
		}
		cursor = resp.Pagination.Cursor
	}
	return all, nil
}

// CreateBackgroundCheck uploads background check evidence for a user.
func (c *Client) CreateBackgroundCheck(ctx context.Context, userID int, completionDate string, filePath string) (*BackgroundCheck, error) {
	fields := map[string]string{
		"userId":         strconv.Itoa(userID),
		"completionDate": completionDate,
	}
	var bc BackgroundCheck
	if err := c.postMultipart(ctx, "/background-checks", fields, map[string]string{"file": filePath}, &bc); err != nil {
		return nil, fmt.Errorf("create background check: %w", err)
	}
	return &bc, nil
}

// --- Policies ---

// Policy represents a Drata policy.
type Policy struct {
	ID               int          `json:"id"`
	Name             string       `json:"name"`
	Scope            string       `json:"scope"`
	Status           string       `json:"status"`
	CurrentVersionID int          `json:"currentVersionId"`
	Version          string       `json:"version"`
	RenewalDate      string       `json:"renewalDate"`
	PublishedAt      string       `json:"publishedAt"`
	Owner            PersonnelUser `json:"owner"`
	CreatedAt        string       `json:"createdAt"`
}

type PolicyListResponse struct {
	Data       []Policy   `json:"data"`
	Pagination Pagination `json:"pagination"`
}

// ListPolicies returns all published policies.
func (c *Client) ListPolicies(ctx context.Context) ([]Policy, error) {
	var all []Policy
	var cursor string
	for {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp PolicyListResponse
		if err := c.get(ctx, "/policies", q, &resp); err != nil {
			return nil, fmt.Errorf("list policies: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Pagination.Cursor == "" {
			break
		}
		cursor = resp.Pagination.Cursor
	}
	return all, nil
}

// --- Vendors ---

// Vendor represents a Drata vendor.
type Vendor struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Status      string `json:"status"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type VendorListResponse struct {
	Data       []Vendor   `json:"data"`
	Pagination Pagination `json:"pagination"`
}

type CreateVendorRequest struct {
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Category     string `json:"category,omitempty"`
	RiskLevel    string `json:"riskLevel,omitempty"`
	WebsiteURL   string `json:"websiteUrl,omitempty"`
	ContactName  string `json:"contactName,omitempty"`
	ContactEmail string `json:"contactEmail,omitempty"`
}

// ListVendors returns all vendors.
func (c *Client) ListVendors(ctx context.Context) ([]Vendor, error) {
	var all []Vendor
	var cursor string
	for {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp VendorListResponse
		if err := c.get(ctx, c.wsPath("/vendors"), q, &resp); err != nil {
			return nil, fmt.Errorf("list vendors: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Pagination.Cursor == "" {
			break
		}
		cursor = resp.Pagination.Cursor
	}
	return all, nil
}

// CreateVendor creates a new vendor.
func (c *Client) CreateVendor(ctx context.Context, req CreateVendorRequest) (*Vendor, error) {
	var v Vendor
	if err := c.post(ctx, c.wsPath("/vendors"), req, &v); err != nil {
		return nil, fmt.Errorf("create vendor: %w", err)
	}
	return &v, nil
}

// --- Risks ---

// Risk represents a Drata risk entry.
type Risk struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Status      string `json:"status"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type RiskListResponse struct {
	Data       []Risk     `json:"data"`
	Pagination Pagination `json:"pagination"`
}

type CreateRiskRequest struct {
	Name                    string `json:"name"`
	Description             string `json:"description,omitempty"`
	Category                string `json:"category,omitempty"`
	InherentLikelihood      int    `json:"inherentLikelihood,omitempty"`
	InherentImpact          int    `json:"inherentImpact,omitempty"`
	ResidualLikelihood      int    `json:"residualLikelihood,omitempty"`
	ResidualImpact          int    `json:"residualImpact,omitempty"`
	TreatmentPlan           string `json:"treatmentPlan,omitempty"`
	TreatmentPlanOwnerID    int    `json:"treatmentPlanOwnerId,omitempty"`
	ControlIDs              []string `json:"controlIds,omitempty"`
}

// ListRisks returns all risks.
func (c *Client) ListRisks(ctx context.Context) ([]Risk, error) {
	var all []Risk
	var cursor string
	for {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp RiskListResponse
		if err := c.get(ctx, c.wsPath("/risks"), q, &resp); err != nil {
			return nil, fmt.Errorf("list risks: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Pagination.Cursor == "" {
			break
		}
		cursor = resp.Pagination.Cursor
	}
	return all, nil
}

// CreateRisk creates a new risk entry.
func (c *Client) CreateRisk(ctx context.Context, req CreateRiskRequest) (*Risk, error) {
	var r Risk
	if err := c.post(ctx, c.wsPath("/risks"), req, &r); err != nil {
		return nil, fmt.Errorf("create risk: %w", err)
	}
	return &r, nil
}

// --- Assets ---

// Asset represents a Drata asset.
type Asset struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	AssetType   string `json:"assetType"`
	Status      string `json:"status"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type AssetListResponse struct {
	Data       []Asset    `json:"data"`
	Pagination Pagination `json:"pagination"`
}

type CreateAssetRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	AssetType   string `json:"assetType"`
	OwnerID     int    `json:"ownerId,omitempty"`
}

// ListAssets returns all assets.
func (c *Client) ListAssets(ctx context.Context) ([]Asset, error) {
	var all []Asset
	var cursor string
	for {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp AssetListResponse
		if err := c.get(ctx, c.wsPath("/assets"), q, &resp); err != nil {
			return nil, fmt.Errorf("list assets: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Pagination.Cursor == "" {
			break
		}
		cursor = resp.Pagination.Cursor
	}
	return all, nil
}

// CreateAsset creates a new asset.
func (c *Client) CreateAsset(ctx context.Context, req CreateAssetRequest) (*Asset, error) {
	var a Asset
	if err := c.post(ctx, c.wsPath("/assets"), req, &a); err != nil {
		return nil, fmt.Errorf("create asset: %w", err)
	}
	return &a, nil
}

// --- Frameworks ---

// Framework represents a Drata compliance framework.
type Framework struct {
	ID                         int    `json:"id"`
	Name                       string `json:"name"`
	Description                string `json:"description"`
	Slug                       string `json:"slug"`
	Tag                        string `json:"tag"`
	NumInScopeControls         int    `json:"numInScopeControls"`
	NumInScopeRequirements     int    `json:"numInScopeRequirements"`
	NumReadyInScopeRequirements int   `json:"numReadyInScopeRequirements"`
	IsReady                    bool   `json:"isReady"`
	IsEnabled                  bool   `json:"isEnabled"`
}

type FrameworkListResponse struct {
	Data       []Framework `json:"data"`
	Pagination Pagination  `json:"pagination"`
}

// ListFrameworks returns all available frameworks.
func (c *Client) ListFrameworks(ctx context.Context) ([]Framework, error) {
	var all []Framework
	var cursor string
	for {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp FrameworkListResponse
		if err := c.get(ctx, c.wsPath("/frameworks"), q, &resp); err != nil {
			return nil, fmt.Errorf("list frameworks: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Pagination.Cursor == "" {
			break
		}
		cursor = resp.Pagination.Cursor
	}
	return all, nil
}

// --- Monitoring Tests ---

// MonitoringTest represents a Drata monitoring test.
type MonitoringTest struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	CheckResultStatus string `json:"checkResultStatus"`
	TestID            int    `json:"testId"`
	CreatedAt         string `json:"createdAt"`
	UpdatedAt         string `json:"updatedAt"`
}

type MonitoringTestListResponse struct {
	Data       []MonitoringTest `json:"data"`
	Pagination Pagination       `json:"pagination"`
}

// ListMonitoringTests returns all monitoring tests.
func (c *Client) ListMonitoringTests(ctx context.Context) ([]MonitoringTest, error) {
	var all []MonitoringTest
	var cursor string
	for {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp MonitoringTestListResponse
		if err := c.get(ctx, c.wsPath("/monitoring-tests"), q, &resp); err != nil {
			return nil, fmt.Errorf("list monitoring tests: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Pagination.Cursor == "" {
			break
		}
		cursor = resp.Pagination.Cursor
	}
	return all, nil
}
