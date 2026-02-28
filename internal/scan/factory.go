package scan

import (
	"log/slog"
	"time"
)

// ScanToolFactory creates scan strategies based on the scan type.
type ScanToolFactory struct {
	currentOptions ScanOptions
}

func NewScanToolFactory() *ScanToolFactory {
	return &ScanToolFactory{}
}

func (f *ScanToolFactory) SetOptions(opts ScanOptions) {
	f.currentOptions = opts
}

// CreateTool returns a ScanStrategy based on the provided scan type.
func (f *ScanToolFactory) CreateTool(toolType string) ScanStrategy {
	switch toolType {
	case "enumeration", "port_scan":
		// Both "enumeration" and "port_scan" use Naabu for port discovery
		return &NaabuStrategy{
			Ports:   f.currentOptions.PortRange,
			Retries: f.currentOptions.MaxRetries,
		}
	case "vulnerability":
		// Create NmapStrategy with protocols and port range
		nmapStrategy := &NmapStrategy{
			Protocols: []string{"*"},              // Default to all protocols
			PortRange: f.currentOptions.PortRange, // Pass port range from template
		}

		// Check if SMB scanning is requested
		for _, scanType := range f.currentOptions.ScanTypes {
			if scanType == "smb" {
				// If SMB is specifically requested, focus on SMB protocol
				nmapStrategy.Protocols = []string{"smb"}
				slog.Debug("setting NmapStrategy to focus on SMB protocol")
				break
			}
		}

		return nmapStrategy
	case "nuclei":
		// Create NucleiStrategy with options from the template/request
		nConfig := f.currentOptions.NucleiScan
		if nConfig == nil {
			// Fallback to defaults if no config provided
			return &NucleiStrategy{
				Tags:       []string{"cve", "misconfig", "exposure"},
				Severities: []string{"low", "medium", "high", "critical"},
				RateLimit:  150,
			}
		}

		return &NucleiStrategy{
			Templates:        nConfig.Templates,
			Tags:             nConfig.Tags,
			Severities:       nConfig.Severities,
			RateLimit:        nConfig.RateLimit,
			Concurrency:      nConfig.Concurrency,
			BulkSize:         nConfig.BulkSize,
			InteractshServer: nConfig.InteractshServer,
			Fuzzing:          nConfig.Fuzzing,
			FollowRedirects:  nConfig.FollowRedirects,
		}
	case "fingerprint":
		// Fingerprint strategy is handled differently since it has a separate interface.
		// The manager uses CreateFingerprintTool() for this scan type.
		// This case is here for completeness but should not be used directly.
		slog.Warn("fingerprint type requested via CreateTool - use CreateFingerprintTool instead")
		return nil
	default:
		slog.Warn("no valid scan strategy for type", "tool_type", toolType)
		return nil
	}
}

// CreateFingerprintTool returns a FingerprintStrategy for host fingerprinting.
// This is separate from CreateTool because FingerprintStrategy has a different interface.
// Uses ping++ for real ICMP/TCP probing and TTL-based OS detection.
func (f *ScanToolFactory) CreateFingerprintTool() FingerprintStrategy {
	// Build fingerprint options from scan options
	opts := DefaultFingerprintOptions()

	// Apply custom probe types if specified
	if len(f.currentOptions.FingerprintProbes) > 0 {
		opts.ProbeTypes = f.currentOptions.FingerprintProbes
	}

	// Parse and apply timeout if specified
	if f.currentOptions.FingerprintTimeout != "" {
		if timeout, err := time.ParseDuration(f.currentOptions.FingerprintTimeout); err == nil {
			opts.Timeout = timeout
		} else {
			slog.Warn("invalid fingerprint timeout, using default",
				"timeout", f.currentOptions.FingerprintTimeout, "default", DefaultFingerprintTimeout)
		}
	}

	// Apply ICMP disable flag
	opts.DisableICMP = f.currentOptions.DisableICMP

	return NewPingPlusPlusAdapterWithOptions(opts)
}
