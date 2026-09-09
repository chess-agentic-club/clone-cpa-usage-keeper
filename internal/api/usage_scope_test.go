package api

import (
	"strings"
	"testing"

	"cpa-usage-keeper/internal/entities"
)

func TestUsageScopeOptionsNeverUseCanonicalOrSourceKeyMaterialAsLabels(t *testing.T) {
	canonical := "litellm:" + strings.Repeat("a", 64)
	options := buildUsageScopeKeyOptions([]entities.SourceAPIKey{
		{ID: "opaque-a", SourceKeyRef: "source-ref-a", UsageGroupRef: canonical, DisplayName: canonical},
		{ID: "opaque-b", SourceKeyRef: "source-ref-b", UsageGroupRef: "internal-b", DisplayName: "Engineering"},
	})
	if len(options) != 2 {
		t.Fatalf("scope options = %#v, want two", options)
	}
	if options[0].ID != "opaque-a" || options[0].Label != "API key" {
		t.Fatalf("credential-shaped option = %#v, want opaque ID and generic label", options[0])
	}
	if options[1].ID != "opaque-b" || options[1].Label != "Engineering" {
		t.Fatalf("benign option = %#v", options[1])
	}
	for _, option := range options {
		if strings.Contains(option.Label, option.ID) || strings.Contains(option.Label, "source-ref") || strings.Contains(option.Label, strings.Repeat("a", 64)) {
			t.Fatalf("scope option leaked an identifier: %#v", option)
		}
	}
}

func TestUsageScopeUserOptionsUseOnlyOpaqueIDAndBenignDisplayLabel(t *testing.T) {
	options := buildUsageScopeUserOptions([]entities.SourceUser{{
		ID: "opaque-user", SourceUserRef: "source-user-ref", Email: "alice@example.com", DisplayName: "Alice",
	}})
	if len(options) != 1 || options[0].ID != "opaque-user" || options[0].Label != "Alice" {
		t.Fatalf("user options = %#v", options)
	}
}
