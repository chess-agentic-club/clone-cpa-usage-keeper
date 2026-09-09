package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIdentityMappingUpdateAcceptsOnlyOpaqueSourceUserCatalogID(t *testing.T) {
	valid := httptest.NewRequest("PUT", "/", strings.NewReader(`{"source_user_catalog_id":"opaque-user"}`))
	request, err := decodeIdentityMappingUpdate(valid)
	if err != nil || request.SourceUserCatalogID != "opaque-user" {
		t.Fatalf("valid mapping update = %#v, %v", request, err)
	}

	for _, body := range []string{
		`{}`,
		`{"source_user_catalog_id":""}`,
		`{"source_user_catalog_id":"opaque-user","source_user_ref":"forged"}`,
		`{"source_user_catalog_id":"opaque-user"}{"source_user_catalog_id":"second"}`,
	} {
		request := httptest.NewRequest("PUT", "/", strings.NewReader(body))
		if _, err := decodeIdentityMappingUpdate(request); err == nil {
			t.Fatalf("decodeIdentityMappingUpdate(%s) unexpectedly succeeded", body)
		}
	}
}

func TestIdentityMappingLabelsRejectCanonicalKeyAndHashValues(t *testing.T) {
	for _, value := range []string{"sk-secret-value", strings.Repeat("a", 64), "litellm:" + strings.Repeat("b", 64)} {
		if got := safeUsageScopeLabel(value, "External identity"); got != "External identity" {
			t.Fatalf("safeUsageScopeLabel(%q) = %q", value, got)
		}
	}
}
