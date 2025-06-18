package scrypto

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestGenerateHash(t *testing.T) {
	t.Parallel()
	t.Run("successful password hashing", func(t *testing.T) {
		password := "mySecurePassword123" //nolint:goconst
		hash, err := Hash(password, bcrypt.DefaultCost)

		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.True(t, ValidateHash(password, hash))
	})

	t.Run("with minimum cost", func(t *testing.T) {
		password := "mySecurePassword123" //nolint:goconst
		hash, err := Hash(password, bcrypt.MinCost)

		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.True(t, ValidateHash(password, hash))
	})

	t.Run("with invalid cost below minimum", func(t *testing.T) {
		password := "mySecurePassword123" //nolint:goconst
		hash, err := Hash(password, bcrypt.MinCost-1)

		assert.Error(t, err)
		assert.Empty(t, hash)
	})

	t.Run("with invalid cost above maximum", func(t *testing.T) {
		password := "mySecurePassword123" //nolint:goconst
		hash, err := Hash(password, bcrypt.MaxCost+1)
		assert.Error(t, err)
		assert.Empty(t, hash)
	})

	t.Run("with empty password", func(t *testing.T) {
		password := ""
		hash, err := Hash(password, bcrypt.DefaultCost)

		require.ErrorIs(t, err, ErrEmptyPassword)
		assert.Empty(t, hash)
		assert.False(t, ValidateHash(password, hash))
	})
}

func TestGenerateRandomPassword(t *testing.T) {
	t.Parallel()
	t.Run("zero length", func(t *testing.T) {
		pass, err := GenerateRandomPassword(0)
		require.NoError(t, err)
		assert.Equal(t, "", pass)
	})

	t.Run("valid length", func(t *testing.T) {
		length := 16
		pass, err := GenerateRandomPassword(length)
		require.NoError(t, err)
		assert.Len(t, pass, length)
	})

	t.Run("multiple generations are different", func(t *testing.T) {
		length := 32
		pass1, err := GenerateRandomPassword(length)
		require.NoError(t, err)
		pass2, err := GenerateRandomPassword(length)
		require.NoError(t, err)
		// There's a chance that the passwords will be equal, but it's extremely unlikely.
		assert.NotEqual(t, pass1, pass2)
	})
}

func TestSetSignedCookie_Success(t *testing.T) {
	t.Parallel()
	secretKey := []byte("myVerySecretKey123")
	originalValue := "cookieValue123"
	cookie := http.Cookie{
		Name:  "testCookie",
		Value: originalValue,
	}

	// Use httptest.ResponseRecorder as our ResponseWriter.
	recorder := httptest.NewRecorder()
	err := SetSignedCookie(recorder, cookie, secretKey)
	require.NoError(t, err)

	// Retrieve the cookie that was set.
	result := recorder.Result()
	cookies := result.Cookies()
	require.Len(t, cookies, 1)

	// Create a request and set the cookie header.
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.AddCookie(cookies[0])

	// Use GetSignedCookie to verify that the cookie was signed correctly.
	value, err := GetSignedCookie(req, cookie.Name, secretKey)
	require.NoError(t, err)
	assert.Equal(t, originalValue, value)
}

func TestSetSignedCookie_ValueTooLong(t *testing.T) {
	t.Parallel()
	secretKey := []byte("myVerySecretKey123")
	// Generate a very long cookie value.
	longValue := strings.Repeat("a", 5000)
	cookie := http.Cookie{
		Name:  "longCookie",
		Value: longValue,
	}

	recorder := httptest.NewRecorder()
	err := SetSignedCookie(recorder, cookie, secretKey)
	assert.Error(t, err)
	assert.Equal(t, ErrValueTooLong, err)
}

func TestGetSignedCookie_InvalidSignature(t *testing.T) {
	t.Parallel()
	secretKey := []byte("myVerySecretKey123")
	// Generate a valid cookie.
	validCookie := http.Cookie{
		Name:  "testCookie",
		Value: "cookieValue123",
	}
	recorder := httptest.NewRecorder()
	err := SetSignedCookie(recorder, validCookie, secretKey)
	require.NoError(t, err)

	// Retrieve the cookie that was set.
	result := recorder.Result()
	cookies := result.Cookies()
	require.Len(t, cookies, 1)

	// Create a request and set the cookie header.
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.AddCookie(cookies[0])

	// Modify the cookie value to create an invalid signature.
	cookies[0].Value = "invalidValue"
	req.AddCookie(cookies[0])

	// Use GetSignedCookie to verify that the cookie was signed correctly.
	_, err = GetSignedCookie(req, validCookie.Name, secretKey[:len(secretKey)-1]) // Use a shorter secret key to invalidate the signature
	require.Error(t, err)
	assert.Equal(t, ErrInvalidValue, err)
}

func TestGetSignedCookie_MissingCookie(t *testing.T) {
	t.Parallel()
	secretKey := []byte("myVerySecretKey123")
	// Create a request without any cookies.
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Use GetSignedCookie to try to retrieve a non-existent cookie.
	_, err := GetSignedCookie(req, "missingCookie", secretKey)
	require.Error(t, err)
	assert.Equal(t, ErrInvalidCookieName, err)
}

func TestReadCookieValue_invalidBase64(t *testing.T) {
	t.Parallel()
	// Create a request with an invalid base64 cookie value.
	req := httptest.NewRequest("GET", "http://example.com", nil)
	cookie := &http.Cookie{
		Name:  "testCookie",
		Value: "invalidBase64Value",
	}
	req.AddCookie(cookie)

	// Attempt to read the cookie value.
	value, err := ReadCookieValue(req, cookie.Name)
	require.Error(t, err)
	assert.Equal(t, ErrInvalidValue, err)
	assert.Empty(t, value)
}

func TestGetSignedCookie_InvalidValueTooShort(t *testing.T) {
	t.Parallel()
	secretKey := []byte("secretkey")
	// Create an HTTP request.
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// Create a cookie with a value that's too short once base64-decoded.
	// We first encode a short string (fewer than sha256.Size bytes) to mimic the signed value.
	shortValue := []byte("short")
	encodedValue := base64.StdEncoding.EncodeToString(shortValue)

	cookie := http.Cookie{
		Name:  "testCookie",
		Value: encodedValue,
	}
	req.AddCookie(&cookie)

	_, err := GetSignedCookie(req, "testCookie", secretKey)
	if err != ErrInvalidValue {
		t.Fatalf("expected ErrInvalidValue, got: %v", err)
	}
}
