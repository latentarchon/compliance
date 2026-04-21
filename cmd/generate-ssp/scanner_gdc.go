package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func scanGDCDeployment(backendRoot string, facts *InfraFacts) {
	gdcDir := filepath.Join(backendRoot, "deploy", "gdc")

	valuesPath := filepath.Join(gdcDir, "values.yaml")
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return
	}

	facts.GDCPlatform = true
	content := string(data)

	facts.GDCRegistryHost = yamlValue(content, "registry")
	facts.GDCProject = yamlNestedValue(content, "gdc", "project")
	facts.GDCLocation = yamlNestedValue(content, "gdc", "location")
	facts.GDCStorageBucket = yamlNestedValue(content, "gdc", "storageBucket")
	facts.GDCEmbeddingModel = yamlNestedValue(content, "gdc", "embeddingModel")
	facts.GDCEmbeddingDimensions, _ = strconv.Atoi(yamlNestedValue(content, "gdc", "embeddingDimensions"))
	facts.GDCExtractorModel = yamlNestedValue(content, "gdc", "extractorModel")

	facts.GDCAlloyDBHost = yamlNestedValue(content, "database", "host")
	facts.GDCAlloyDBSSLMode = yamlNestedValue(content, "database", "sslMode")

	facts.GDCAppReplicas, _ = strconv.Atoi(yamlNestedValue(content, "app", "replicas"))
	facts.GDCAdminReplicas, _ = strconv.Atoi(yamlNestedValue(content, "admin", "replicas"))
	facts.GDCOpsReplicas, _ = strconv.Atoi(yamlNestedValue(content, "ops", "replicas"))
	facts.GDCWorkerReplicas, _ = strconv.Atoi(yamlNestedValue(content, "worker", "replicas"))
	facts.GDCWorkerEnabled = yamlNestedValue(content, "worker", "enabled") == "true"

	facts.GDCGatewayEnabled = yamlNestedValue(content, "gateway", "enabled") == "true"
	facts.GDCGatewayClassName = yamlNestedValue(content, "gateway", "className")
	facts.GDCAppHost = yamlDeepValue(content, "gateway", "hosts", "app")
	facts.GDCAdminHost = yamlDeepValue(content, "gateway", "hosts", "admin")

	facts.GDCNetworkPolicyEnabled = yamlNestedValue(content, "networkPolicy", "enabled") == "true"
	facts.GDCPDBEnabled = yamlNestedValue(content, "pdb", "enabled") == "true"

	facts.GDCSessionIdleTimeout, _ = strconv.Atoi(yamlNestedValue(content, "session", "idleTimeoutMin"))
	facts.GDCSessionAbsTimeout, _ = strconv.Atoi(yamlNestedValue(content, "session", "absoluteTimeoutMin"))
	facts.GDCMaxConcurrentSess, _ = strconv.Atoi(yamlNestedValue(content, "session", "maxConcurrentSessions"))

	facts.GDCDoDCAMounted = yamlNestedValue(content, "cac", "trustedCASecretName") != ""

	scanGDCGatewayTemplate(gdcDir, facts)
	scanGDCSecurityContext(gdcDir, facts)
	scanGDCManifestCounts(gdcDir, facts)
}

func scanGDCGatewayTemplate(gdcDir string, facts *InfraFacts) {
	path := filepath.Join(gdcDir, "templates", "gateway.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)
	if strings.Contains(content, "client-ca-secret") || strings.Contains(content, "clientCASecretName") {
		facts.GDCGatewayMTLS = true
	}
}

func scanGDCSecurityContext(gdcDir string, facts *InfraFacts) {
	templatesDir := filepath.Join(gdcDir, "templates")
	entries, err := os.ReadDir(templatesDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "deployment-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(templatesDir, e.Name()))
		if err != nil {
			continue
		}
		content := string(data)
		if strings.Contains(content, "runAsNonRoot: true") &&
			strings.Contains(content, "readOnlyRootFilesystem: true") &&
			strings.Contains(content, "drop:") {
			facts.GDCSecurityContext = true
			return
		}
	}
}

func scanGDCManifestCounts(gdcDir string, facts *InfraFacts) {
	templatesDir := filepath.Join(gdcDir, "templates")
	entries, err := os.ReadDir(templatesDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(templatesDir, e.Name()))
		if err != nil {
			continue
		}
		content := string(data)
		facts.GDCDeploymentCount += strings.Count(content, "kind: Deployment")
		facts.GDCServiceCount += strings.Count(content, "kind: Service")
	}
}

// yamlValue extracts a simple "key: value" from YAML content.
func yamlValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key+":") {
			val := strings.TrimPrefix(trimmed, key+":")
			val = strings.TrimSpace(val)
			val = strings.Trim(val, `"'`)
			return val
		}
	}
	return ""
}

// yamlNestedValue extracts "parent:\n  key: value" from YAML content.
func yamlNestedValue(content, parent, key string) string {
	lines := strings.Split(content, "\n")
	inParent := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if indent == 0 && strings.HasPrefix(trimmed, parent+":") {
			inParent = true
			continue
		}
		if indent == 0 && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			inParent = false
			continue
		}
		if inParent && indent > 0 && strings.HasPrefix(trimmed, key+":") {
			val := strings.TrimPrefix(trimmed, key+":")
			val = strings.TrimSpace(val)
			val = strings.Trim(val, `"'`)
			return val
		}
	}
	return ""
}

// yamlDeepValue extracts a three-level nested value: "a:\n  b:\n    c: value"
func yamlDeepValue(content, l1, l2, l3 string) string {
	lines := strings.Split(content, "\n")
	inL1 := false
	inL2 := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if indent == 0 && strings.HasPrefix(trimmed, l1+":") {
			inL1 = true
			inL2 = false
			continue
		}
		if indent == 0 && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			inL1 = false
			inL2 = false
			continue
		}
		if inL1 && indent > 0 && indent <= 2 && strings.HasPrefix(trimmed, l2+":") {
			inL2 = true
			continue
		}
		if inL1 && indent > 0 && indent <= 2 && !strings.HasPrefix(trimmed, l2+":") && !strings.HasPrefix(trimmed, "#") {
			if !strings.HasPrefix(trimmed, l3+":") {
				inL2 = false
			}
		}
		if inL1 && inL2 && indent > 2 && strings.HasPrefix(trimmed, l3+":") {
			val := strings.TrimPrefix(trimmed, l3+":")
			val = strings.TrimSpace(val)
			val = strings.Trim(val, `"'`)
			return val
		}
	}
	return ""
}
