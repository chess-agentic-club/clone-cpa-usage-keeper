package dto

// UsageScopeMode determines whether a trusted usage query is constrained to
// resolved API group keys or intentionally includes an entire source system.
type UsageScopeMode string

const (
	UsageScopeAllSource UsageScopeMode = "all_source"
	UsageScopeKeySet    UsageScopeMode = "key_set"
)

// UsageScope is built by server policy. APIGroupKeys are resolved only after
// catalog ownership checks, never accepted from a browser request.
type UsageScope struct {
	Mode         UsageScopeMode
	SourceSystem string
	APIGroupKeys []string
}
