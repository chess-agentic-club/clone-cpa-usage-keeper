package api

import "testing"

func TestEmbeddedAuthCapabilitiesDisableViewerKeyLogin(t *testing.T) {
	standalone := SourceCapabilitiesForAuthMode(SourceCapabilitiesForUsageSource("litellm"), AuthModeStandalone)
	if !standalone.ViewerKeyLogin {
		t.Fatalf("standalone LiteLLM must retain viewer-key login: %+v", standalone)
	}
	embedded := SourceCapabilitiesForAuthMode(standalone, AuthModeEmbeddedJWT)
	if embedded.ViewerKeyLogin {
		t.Fatalf("embedded mode must not advertise viewer-key login: %+v", embedded)
	}
	if !embedded.APIKeyAnalytics {
		t.Fatalf("auth-mode gating must preserve unrelated source capabilities: %+v", embedded)
	}
}
