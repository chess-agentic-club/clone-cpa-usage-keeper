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
		{ID: "opaque-c", SourceKeyRef: "source-ref-c", UsageGroupRef: "internal-c", DisplayName: "Team source-ref-c legacy"},
		{ID: "opaque-d", SourceKeyRef: "source-ref-d", UsageGroupRef: "internal-d", DisplayName: "Team internal-d legacy"},
		{ID: "opaque-e", SourceKeyRef: "source-ref-e", UsageGroupRef: "internal-e", DisplayName: "Team sk-" + strings.Repeat("q", 48) + " legacy"},
		{ID: "opaque-f", SourceKeyRef: "source-ref-f", UsageGroupRef: "internal-f", DisplayName: "Team " + strings.Repeat("b", 64) + " legacy"},
	})
	if len(options) != 6 {
		t.Fatalf("scope options = %#v, want six", options)
	}
	if options[0].ID != "opaque-a" || options[0].Label != "API key" {
		t.Fatalf("credential-shaped option = %#v, want opaque ID and generic label", options[0])
	}
	if options[1].ID != "opaque-b" || options[1].Label != "Engineering" {
		t.Fatalf("benign option = %#v", options[1])
	}
	for _, option := range options[2:] {
		if option.Label != "API key" {
			t.Fatalf("legacy sensitive option = %#v, want generic label", option)
		}
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
