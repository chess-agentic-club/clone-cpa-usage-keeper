package api

import "strings"

const (
	AuthModeStandalone  = "standalone"
	AuthModeEmbeddedJWT = "embedded_jwt"
)

// SourceCapabilities describes which source-dependent dashboard features are
// meaningful for the configured, deployment-time usage source.
type SourceCapabilities struct {
	APIKeyAnalytics bool `json:"api_key_analytics"`
	CPAAuthFiles    bool `json:"cpa_auth_files"`
	CPAQuota        bool `json:"cpa_quota"`
	LiteLLMUsers    bool `json:"litellm_users"`
	LiteLLMTeams    bool `json:"litellm_teams"`
	ViewerKeyLogin  bool `json:"viewer_key_login"`
}

// SourceCapabilitiesForUsageSource returns the supported feature set for a
// known source. The application configuration validates source values before
// this function is called, while the CLIProxy default keeps direct router
// construction backward compatible for tests and integrations.
func SourceCapabilitiesForUsageSource(usageSource string) SourceCapabilities {
	switch strings.ToLower(strings.TrimSpace(usageSource)) {
	case "litellm":
		return SourceCapabilities{APIKeyAnalytics: true, ViewerKeyLogin: true}
	case "", "cliproxy":
		return SourceCapabilities{
			APIKeyAnalytics: true,
			CPAAuthFiles:    true,
			CPAQuota:        true,
			ViewerKeyLogin:  true,
		}
	default:
		return SourceCapabilities{}
	}
}

func sourceCapabilitiesForStatus(config StatusRouteConfig) SourceCapabilities {
	if config.UsageSource == "" || config.Capabilities == (SourceCapabilities{}) {
		return SourceCapabilitiesForUsageSource(config.UsageSource)
	}
	return config.Capabilities
}

// SourceCapabilitiesForAuthMode removes standalone-only authentication
// affordances from the public capability set in embedded deployments.
func SourceCapabilitiesForAuthMode(capabilities SourceCapabilities, authMode string) SourceCapabilities {
	if normalizeAuthMode(authMode) == AuthModeEmbeddedJWT {
		capabilities.ViewerKeyLogin = false
	}
	return capabilities
}

func normalizeAuthMode(authMode string) string {
	if strings.TrimSpace(authMode) == AuthModeEmbeddedJWT {
		return AuthModeEmbeddedJWT
	}
	return AuthModeStandalone
}

// HasCPAIntegration identifies routes backed by CPA-only APIs. Both supported
// sources are source-exclusive, so either CPA feature establishes this mode.
func (c SourceCapabilities) HasCPAIntegration() bool {
	return c.CPAAuthFiles || c.CPAQuota
}
