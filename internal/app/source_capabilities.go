package app

import (
	"cpa-usage-keeper/internal/api"
	"cpa-usage-keeper/internal/config"
)

// SourceCapabilities is the source metadata owned by the runtime and exposed
// by the API status endpoint for capability-gated consumers.
type SourceCapabilities = api.SourceCapabilities

func sourceCapabilitiesFor(cfg config.Config) SourceCapabilities {
	switch cfg.UsageSource {
	case "cliproxy", "litellm":
		return api.SourceCapabilitiesForUsageSource(cfg.UsageSource)
	default:
		// New sources stay capability-disabled until their viewer adapter and
		// source-specific dashboard semantics have been explicitly registered.
		return SourceCapabilities{}
	}
}
