package scrypto

import (
	"context"
	"crypto/rsa"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ValidateContextGRPC validates the JWT token from the incoming gRPC context
// It extracts the token from the context and parses it using the provided public key
// If the token is valid, it returns the JWT struct
func ValidateContextGRPC(ctx context.Context, publicKey *rsa.PublicKey) (*JWT, error) {
	token, err := JWTokenStringFromIncomingContext(ctx)
	if err != nil {
		return nil, err
	}
	return ParseAuthToken(token, publicKey)
}

// JWTokenStringFromIncomingContext extracts the JWT token from the incoming gRPC context
// It looks for the "Authorization" metadata key and returns the token string
// If the token is not found, it returns an error
func JWTokenStringFromIncomingContext(ctx context.Context) (string, error) {
	mtd, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "could_not_get_metadata_from_context")
	}

	tokens := mtd.Get("Authorization")
	if len(tokens) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing_authorization_token")
	}

	return strings.TrimPrefix(tokens[0], "Bearer "), nil
}
