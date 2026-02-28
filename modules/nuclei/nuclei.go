package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/SiriusScan/go-api/sirius"
)

// ScanConfig holds the configuration for the Nuclei scan
type ScanConfig struct {
	Target           string
	Templates        []string
	Tags             []string
	Severities       []string
	RateLimit        int
	Concurrency      int
	BulkSize         int
	InteractshServer string
	Fuzzing          bool
	FollowRedirects  bool
	Ctx              context.Context
}

// nucleiResult represents the JSONL output from Nuclei
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	MatchedHost string `json:"matched-at"`
	IP          string `json:"ip"`
	Timestamp   string `json:"timestamp"`
}

// ScanWithConfig performs a Nuclei scan using the provided configuration
func ScanWithConfig(config ScanConfig) (sirius.Host, error) {
	host := sirius.Host{
		IP: config.Target,
	}

	ctx := config.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	args := []string{
		"-target", config.Target,
		"-jsonl",
		"-no-color",
	}

	if len(config.Templates) > 0 {
		args = append(args, "-t", strings.Join(config.Templates, ","))
	}
	if len(config.Tags) > 0 {
		args = append(args, "-tags", strings.Join(config.Tags, ","))
	}
	if len(config.Severities) > 0 {
		args = append(args, "-severity", strings.Join(config.Severities, ","))
	}
	if config.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", config.RateLimit))
	}
	if config.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", config.Concurrency))
	}
	if config.BulkSize > 0 {
		args = append(args, "-bs", fmt.Sprintf("%d", config.BulkSize))
	}
	if config.InteractshServer != "" {
		args = append(args, "-iserver", config.InteractshServer)
	}
	if config.Fuzzing {
		args = append(args, "-dast")
	}
	if config.FollowRedirects {
		args = append(args, "-fr")
	}

	slog.Info("executing nuclei command", "args", strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return host, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return host, fmt.Errorf("failed to start nuclei: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		var res nucleiResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			slog.Warn("failed to parse nuclei output line", "line", line, "error", err)
			continue
		}

		vuln := sirius.Vulnerability{
			VID:         res.TemplateID,
			Title:       res.Info.Name,
			Description: res.Info.Description,
			RiskScore:   mapSeverity(res.Info.Severity),
		}

		// Add metadata about the match
		if res.MatchedHost != "" {
			vuln.Description = fmt.Sprintf("%s\n\nMatched at: %s", vuln.Description, res.MatchedHost)
		}

		host.Vulnerabilities = append(host.Vulnerabilities, vuln)
	}

	if err := cmd.Wait(); err != nil {
		// Nuclei returns 1 if no vulnerabilities found or if there was an error
		// We should differentiate between the two if possible, but for now we'll just log
		slog.Debug("nuclei command finished with potential notice", "error", err)
	}

	return host, nil
}

func mapSeverity(severity string) float64 {
	switch strings.ToLower(severity) {
	case "info":
		return 1.0
	case "low":
		return 3.0
	case "medium":
		return 5.0
	case "high":
		return 8.0
	case "critical":
		return 10.0
	default:
		return 5.0
	}
}
