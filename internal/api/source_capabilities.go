package api

import "strings"

// SourceCapabilities describes which source-dependent dashboard features are
// meaningful for the configured, deployment-time usage source.
type SourceCapabilities struct {
	APIKeyAnalytics bool `json:"api_key_analytics"`
	CPAAuthFiles    bool `json:"cpa_auth_files"`
	CPAQuota        bool `json:"cpa_quota"`
	LiteLLMUsers    bool `json:"litellm_users"`
	LiteLLMTeams    bool `json:"litellm_teams"`
}

// SourceCapabilitiesForUsageSource returns the supported feature set for a
// known source. The application configuration validates source values before
// this function is called, while the CLIProxy default keeps direct router
// construction backward compatible for tests and integrations.
func SourceCapabilitiesForUsageSource(usageSource string) SourceCapabilities {
	if strings.EqualFold(strings.TrimSpace(usageSource), "litellm") {
		return SourceCapabilities{APIKeyAnalytics: true}
	}
	return SourceCapabilities{
		APIKeyAnalytics: true,
		CPAAuthFiles:    true,
		CPAQuota:        true,
	}
}

func sourceCapabilitiesForStatus(config StatusRouteConfig) SourceCapabilities {
	if config.UsageSource == "" || config.Capabilities == (SourceCapabilities{}) {
		return SourceCapabilitiesForUsageSource(config.UsageSource)
	}
	return config.Capabilities
}

// HasCPAIntegration identifies routes backed by CPA-only APIs. Both supported
// sources are source-exclusive, so either CPA feature establishes this mode.
func (c SourceCapabilities) HasCPAIntegration() bool {
	return c.CPAAuthFiles || c.CPAQuota
}
