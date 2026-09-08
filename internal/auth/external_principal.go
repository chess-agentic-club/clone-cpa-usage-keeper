package auth

import "time"

// ExternalPrincipal is the authenticated identity asserted by a trusted
// external identity provider. It intentionally excludes the bearer token and
// any other credential material used to obtain the assertion.
type ExternalPrincipal struct {
	Issuer          string
	Subject         string
	Email           string
	DisplayName     string
	IsAdministrator bool
	// AssertionExpiresAt is the verified external assertion expiry. Consumers
	// use it as a hard upper bound for any locally issued session.
	AssertionExpiresAt time.Time
}
