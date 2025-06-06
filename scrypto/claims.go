package scrypto

// IsActivationClaims checks if the claims contain an activation purpose.
// It returns true if the purpose is "activation", otherwise false.
func IsActivationClaims(claims map[string]any) bool {
	v, ok := claims[ClaimKeyPurpose.String()]
	return ok && v.(string) == ClaimPurposeActivation.String()
}

// IsAuthenticationClaims checks if the claims contain an authentication purpose.
// It returns true if the purpose is "authentication", otherwise false.
func IsAuthenticationClaims(claims map[string]any) bool {
	v, ok := claims[ClaimKeyPurpose.String()]
	return ok && v.(string) == ClaimPurposeAuthentication.String()
}

// IsRefreshClaims checks if the claims contain a refresh token purpose.
// It returns true if the purpose is "refresh", otherwise false.
func IsRefreshClaims(claims map[string]any) bool {
	v, ok := claims[ClaimKeyPurpose.String()]
	return ok && v.(string) == ClaimPurposeRefresh.String()
}

func getClaim[T any](claims map[string]any, key string) T {
	if value, ok := claims[key]; ok && value != nil {
		if v, ok := value.(T); ok {
			return v
		}
	}
	var zero T
	return zero
}

func GetClaim[T any](claims map[string]any, key string) T {
	return getClaim[T](claims, key)
}
