// TrivyScanner CV — MCP# HTTP Server Wrapper
// 5FS Fork of github.com/aquasecurity/trivy (Apache 2.0)
// HCC Fork: github.com/Hircocervus-Consultancy-Corporation/trivy
// FUND: 3% of derivative revenue to AquaSecurity (Trust Keeper tracked)
//
// Wraps the trivy CLI binary as a mesh-addressable CV:
//   POST /scan/image    — scan a container image
//   POST /scan/fs       — scan a filesystem path
//   GET  /attestation/:id — retrieve a stored attestation
//   GET  /health        — liveness + DB version

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ── types ────────────────────────────────────────────────────────────────────

type ScanImageRequest struct {
	Image    string   `json:"image"`
	Severity []string `json:"severity,omitempty"` // ["HIGH","CRITICAL"] default
	Format   string   `json:"format,omitempty"`   // "json" | "sarif" default "json"
}

type ScanFsRequest struct {
	Path     string   `json:"path"`
	Severity []string `json:"severity,omitempty"`
	Format   string   `json:"format,omitempty"`
}

type Finding struct {
	VulnerabilityID  string `json:"vulnerability_id"`
	PkgName          string `json:"pkg_name"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	Severity         string `json:"severity"`
	Title            string `json:"title,omitempty"`
	Description      string `json:"description,omitempty"`
}

type SeveritySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

type ScanResponse struct {
	AttestationID   string          `json:"attestation_id"`
	ImageRef        string          `json:"image_ref,omitempty"`
	FsPath          string          `json:"fs_path,omitempty"`
	ScanTimestamp   time.Time       `json:"scan_timestamp"`
	TrivyVersion    string          `json:"trivy_version"`
	VulnDBVersion   string          `json:"vuln_db_version"`
	Findings        []Finding       `json:"findings"`
	SeveritySummary SeveritySummary `json:"severity_summary"`
	Passed          bool            `json:"passed"` // true = 0 HIGH/CRITICAL
	RawOutput       json.RawMessage `json:"raw_output,omitempty"`
}

type HealthResponse struct {
	Status       string    `json:"status"`
	TrivyVersion string    `json:"trivy_version"`
	DBVersion    string    `json:"db_version"`
	Timestamp    time.Time `json:"timestamp"`
	Environment  string    `json:"environment"`
}

// ── in-memory attestation store ──────────────────────────────────────────────

type attestationStore struct {
	mu    sync.RWMutex
	store map[string]ScanResponse
}

func newAttestationStore() *attestationStore {
	return &attestationStore{store: make(map[string]ScanResponse)}
}

func (s *attestationStore) put(id string, r ScanResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[id] = r
}

func (s *attestationStore) get(id string) (ScanResponse, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.store[id]
	return r, ok
}

// ── helpers ──────────────────────────────────────────────────────────────────

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func trivyVersion() string {
	out, err := exec.Command("trivy", "--version").Output()
	if err != nil {
		return "unknown"
	}
	// "Version: 0.69.3\n..." → first line
	lines := strings.SplitN(string(out), "\n", 2)
	if len(lines) > 0 {
		return strings.TrimPrefix(strings.TrimSpace(lines[0]), "Version: ")
	}
	return "unknown"
}

func dbVersion() string {
	cacheDir := os.Getenv("TRIVY_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/var/trivy-db"
	}
	// trivy image --download-db-only prints DB metadata; simpler: read metadata.json
	metaPath := cacheDir + "/db/metadata.json"
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return "unknown"
	}
	var meta struct {
		UpdatedAt time.Time `json:"UpdatedAt"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "unknown"
	}
	return meta.UpdatedAt.Format("2006-01-02")
}

func defaultSeverities(requested []string) string {
	if len(requested) == 0 {
		return "HIGH,CRITICAL"
	}
	return strings.Join(requested, ",")
}

func parseTrivyJSON(raw []byte) ([]Finding, SeveritySummary) {
	// Trivy JSON schema: array of Results, each with Vulnerabilities
	var results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
		} `json:"Vulnerabilities"`
	}
	// Trivy wraps results in {"Results": [...]}
	var wrapper struct {
		Results json.RawMessage `json:"Results"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && wrapper.Results != nil {
		_ = json.Unmarshal(wrapper.Results, &results)
	}

	var findings []Finding
	var summary SeveritySummary
	for _, result := range results {
		for _, v := range result.Vulnerabilities {
			findings = append(findings, Finding{
				VulnerabilityID:  v.VulnerabilityID,
				PkgName:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         v.Severity,
				Title:            v.Title,
				Description:      v.Description,
			})
			switch strings.ToUpper(v.Severity) {
			case "CRITICAL":
				summary.Critical++
			case "HIGH":
				summary.High++
			case "MEDIUM":
				summary.Medium++
			case "LOW":
				summary.Low++
			default:
				summary.Unknown++
			}
		}
	}
	return findings, summary
}

func runScan(args []string, format string) ([]byte, error) {
	cacheDir := os.Getenv("TRIVY_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/var/trivy-db"
	}
	cmd := exec.Command("trivy", args...)
	cmd.Env = append(os.Environ(),
		"TRIVY_CACHE_DIR="+cacheDir,
		"TRIVY_NO_PROGRESS=true",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		// Exit code 1 from trivy = vulnerabilities found — that's not a tool error,
		// it's scan data. Only treat as error if stdout is empty.
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("trivy error: %s", stderr.String())
		}
	}
	return stdout.Bytes(), nil
}

func notifyTrustKeeper(attestationID string, passed bool) {
	endpoint := os.Getenv("TRUST_KEEPER_ENDPOINT")
	if endpoint == "" {
		return
	}
	payload := map[string]interface{}{
		"attestation_id": attestationID,
		"type":           "security_scan",
		"passed":         passed,
		"timestamp":      time.Now().UTC(),
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(endpoint+"/attestations/security-scan", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("WARN: Trust Keeper notification failed: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("INFO: Trust Keeper notified, attestation_id=%s status=%d", attestationID, resp.StatusCode)
}

// ── handlers ─────────────────────────────────────────────────────────────────

func (s *attestationStore) handleScanImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ScanImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Image == "" {
		http.Error(w, "invalid request: 'image' required", http.StatusBadRequest)
		return
	}
	format := req.Format
	if format == "" {
		format = "json"
	}
	severity := defaultSeverities(req.Severity)
	args := []string{
		"image",
		"--format", format,
		"--severity", severity,
		"--exit-code", "1",
		req.Image,
	}
	log.Printf("INFO: scanning image=%s severity=%s", req.Image, severity)
	raw, err := runScan(args, format)
	if err != nil {
		http.Error(w, fmt.Sprintf("scan failed: %v", err), http.StatusInternalServerError)
		return
	}
	findings, summary := parseTrivyJSON(raw)
	passed := summary.Critical == 0 && summary.High == 0
	resp := ScanResponse{
		AttestationID:   newID(),
		ImageRef:        req.Image,
		ScanTimestamp:   time.Now().UTC(),
		TrivyVersion:    trivyVersion(),
		VulnDBVersion:   dbVersion(),
		Findings:        findings,
		SeveritySummary: summary,
		Passed:          passed,
		RawOutput:       json.RawMessage(raw),
	}
	s.put(resp.AttestationID, resp)
	go notifyTrustKeeper(resp.AttestationID, passed)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
	log.Printf("INFO: scan complete attestation_id=%s passed=%v critical=%d high=%d",
		resp.AttestationID, passed, summary.Critical, summary.High)
}

func (s *attestationStore) handleScanFs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ScanFsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		http.Error(w, "invalid request: 'path' required", http.StatusBadRequest)
		return
	}
	// Prevent path traversal
	if strings.Contains(req.Path, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	format := req.Format
	if format == "" {
		format = "json"
	}
	severity := defaultSeverities(req.Severity)
	args := []string{
		"fs",
		"--format", format,
		"--severity", severity,
		req.Path,
	}
	log.Printf("INFO: scanning fs path=%s severity=%s", req.Path, severity)
	raw, err := runScan(args, format)
	if err != nil {
		http.Error(w, fmt.Sprintf("scan failed: %v", err), http.StatusInternalServerError)
		return
	}
	findings, summary := parseTrivyJSON(raw)
	passed := summary.Critical == 0 && summary.High == 0
	resp := ScanResponse{
		AttestationID:   newID(),
		FsPath:          req.Path,
		ScanTimestamp:   time.Now().UTC(),
		TrivyVersion:    trivyVersion(),
		VulnDBVersion:   dbVersion(),
		Findings:        findings,
		SeveritySummary: summary,
		Passed:          passed,
		RawOutput:       json.RawMessage(raw),
	}
	s.put(resp.AttestationID, resp)
	go notifyTrustKeeper(resp.AttestationID, passed)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *attestationStore) handleGetAttestation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/attestation/")
	if id == "" {
		http.Error(w, "attestation id required", http.StatusBadRequest)
		return
	}
	// Validate id is hex (prevents injection)
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			http.Error(w, "invalid attestation id", http.StatusBadRequest)
			return
		}
	}
	resp, ok := s.get(id)
	if !ok {
		http.Error(w, "attestation not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := HealthResponse{
		Status:       "ok",
		TrivyVersion: trivyVersion(),
		DBVersion:    dbVersion(),
		Timestamp:    time.Now().UTC(),
		Environment:  os.Getenv("MESH_ENVIRONMENT"),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8500"
	}

	store := newAttestationStore()

	mux := http.NewServeMux()
	mux.HandleFunc("/scan/image", store.handleScanImage)
	mux.HandleFunc("/scan/filesystem", store.handleScanFs)
	mux.HandleFunc("/attestation/", store.handleGetAttestation)
	mux.HandleFunc("/health", handleHealth)

	addr := ":" + port
	log.Printf("INFO: TrivyScanner CV starting on %s (trivy=%s db=%s)", addr, trivyVersion(), dbVersion())
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("FATAL: server died: %v", err)
	}
}
