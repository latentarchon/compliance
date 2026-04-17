package main

// OSCAL SSP type definitions (NIST OSCAL 1.1.3).

type SSPDocument struct {
	SystemSecurityPlan SSP `json:"system-security-plan"`
}

type SSP struct {
	UUID                  string                `json:"uuid"`
	Metadata              Metadata              `json:"metadata"`
	ImportProfile         ImportProfile         `json:"import-profile"`
	SystemCharacteristics SystemCharacteristics `json:"system-characteristics"`
	SystemImplementation  SystemImplementation  `json:"system-implementation"`
	ControlImplementation ControlImplementation `json:"control-implementation"`
}

type Metadata struct {
	Title              string             `json:"title"`
	LastModified       string             `json:"last-modified"`
	Version            string             `json:"version"`
	OscalVersion       string             `json:"oscal-version"`
	Props              []Prop             `json:"props,omitempty"`
	Roles              []Role             `json:"roles,omitempty"`
	Parties            []Party            `json:"parties,omitempty"`
	ResponsibleParties []ResponsibleParty `json:"responsible-parties,omitempty"`
}

type Prop struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Class string `json:"class,omitempty"`
	NS    string `json:"ns,omitempty"`
}

type Role struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type Party struct {
	UUID                    string   `json:"uuid"`
	Type                    string   `json:"type"`
	Name                    string   `json:"name"`
	EmailAddresses          []string `json:"email-addresses,omitempty"`
	Links                   []Link   `json:"links,omitempty"`
	Props                   []Prop   `json:"props,omitempty"`
	MemberOfOrganizations   []string `json:"member-of-organizations,omitempty"`
}

type Link struct {
	Href string `json:"href"`
	Rel  string `json:"rel,omitempty"`
}

type ResponsibleParty struct {
	RoleID     string   `json:"role-id"`
	PartyUUIDs []string `json:"party-uuids"`
}

type ImportProfile struct {
	Href string `json:"href"`
}

type SystemCharacteristics struct {
	SystemIDs              []SystemID             `json:"system-ids"`
	SystemName             string                 `json:"system-name"`
	SystemNameShort        string                 `json:"system-name-short,omitempty"`
	Description            string                 `json:"description"`
	Props                  []Prop                 `json:"props,omitempty"`
	SecuritySensitivity    string                 `json:"security-sensitivity-level"`
	SystemInformation      SystemInformation      `json:"system-information"`
	SecurityImpactLevel    SecurityImpactLevel    `json:"security-impact-level"`
	Status                 Status                 `json:"status"`
	AuthorizationBoundary  DescriptionBlock       `json:"authorization-boundary"`
	NetworkArchitecture    DescriptionBlock       `json:"network-architecture"`
	DataFlow               DescriptionBlock       `json:"data-flow"`
}

type SystemID struct {
	IdentifierType string `json:"identifier-type,omitempty"`
	ID             string `json:"id"`
}

type SystemInformation struct {
	InformationTypes []InformationType `json:"information-types"`
}

type InformationType struct {
	UUID                  string          `json:"uuid"`
	Title                 string          `json:"title"`
	Description           string          `json:"description"`
	Categorizations       []Categorization `json:"categorizations,omitempty"`
	ConfidentialityImpact ImpactLevel     `json:"confidentiality-impact"`
	IntegrityImpact       ImpactLevel     `json:"integrity-impact"`
	AvailabilityImpact    ImpactLevel     `json:"availability-impact"`
}

type Categorization struct {
	System             string   `json:"system"`
	InformationTypeIDs []string `json:"information-type-ids"`
}

type ImpactLevel struct {
	Base string `json:"base"`
}

type SecurityImpactLevel struct {
	Confidentiality string `json:"security-objective-confidentiality"`
	Integrity       string `json:"security-objective-integrity"`
	Availability    string `json:"security-objective-availability"`
}

type Status struct {
	State   string `json:"state"`
	Remarks string `json:"remarks,omitempty"`
}

type DescriptionBlock struct {
	Description string `json:"description"`
}

type SystemImplementation struct {
	LeveragedAuthorizations []LeveragedAuthorization `json:"leveraged-authorizations,omitempty"`
	Users                   []User                   `json:"users"`
	Components              []Component              `json:"components"`
}

type LeveragedAuthorization struct {
	UUID           string `json:"uuid"`
	Title          string `json:"title"`
	Props          []Prop `json:"props,omitempty"`
	Links          []Link `json:"links,omitempty"`
	PartyUUID      string `json:"party-uuid"`
	DateAuthorized string `json:"date-authorized"`
}

type User struct {
	UUID                 string              `json:"uuid"`
	Title                string              `json:"title"`
	Description          string              `json:"description"`
	Props                []Prop              `json:"props,omitempty"`
	RoleIDs              []string            `json:"role-ids,omitempty"`
	AuthorizedPrivileges []AuthorizedPriv    `json:"authorized-privileges,omitempty"`
}

type AuthorizedPriv struct {
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	FunctionsPerformed []string `json:"functions-performed"`
}

type Component struct {
	UUID        string `json:"uuid"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Props       []Prop `json:"props,omitempty"`
	Status      Status `json:"status"`
}

type ControlImplementation struct {
	Description              string                    `json:"description"`
	ImplementedRequirements  []ImplementedRequirement  `json:"implemented-requirements"`
}

type ImplementedRequirement struct {
	UUID             string           `json:"uuid"`
	ControlID        string           `json:"control-id"`
	Props            []Prop           `json:"props,omitempty"`
	SetParameters    []SetParameter   `json:"set-parameters,omitempty"`
	ResponsibleRoles []RoleRef        `json:"responsible-roles,omitempty"`
	Statements       []Statement      `json:"statements"`
}

type SetParameter struct {
	ParamID string   `json:"param-id"`
	Values  []string `json:"values"`
}

type RoleRef struct {
	RoleID string `json:"role-id"`
}

type Statement struct {
	StatementID  string        `json:"statement-id"`
	UUID         string        `json:"uuid"`
	ByComponents []ByComponent `json:"by-components"`
}

type ByComponent struct {
	ComponentUUID        string `json:"component-uuid"`
	UUID                 string `json:"uuid"`
	Description          string `json:"description"`
	ImplementationStatus ImplStatus `json:"implementation-status"`
}

type ImplStatus struct {
	State string `json:"state"`
}
