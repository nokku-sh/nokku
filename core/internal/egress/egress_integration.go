//go:build integration

package egress

// AllowPrivateWhenHosted lets a hosted test server reach the identity
// providers and sinks its tests run on loopback.
func AllowPrivateWhenHosted() { privateWhenHosted = true }
