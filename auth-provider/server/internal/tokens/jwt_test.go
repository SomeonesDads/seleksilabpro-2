package tokens

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testKey      = "a sufficiently long test signing key"
	testIssuer   = "auth-provider"
	testAudience = "application-uuid"
)

func TestIssueAndValidateAccessToken(t *testing.T) {
	tokenString, err := IssueAccessToken([]byte(testKey), testIssuer, "user-uuid", testAudience, "sso-session-uuid", time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	claims, err := ValidateAccessToken(tokenString, []byte(testKey), testIssuer, testAudience)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if claims.Subject != "user-uuid" || claims.Audience[0] != testAudience || claims.Issuer != testIssuer || claims.Scope != DefaultScope || claims.SID != "sso-session-uuid" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.ID == "" || claims.ExpiresAt == nil || claims.IssuedAt == nil {
		t.Fatalf("required registered claims are missing: %+v", claims)
	}
}

func TestIssueAccessTokenGeneratesUniqueJTI(t *testing.T) {
	first, err := IssueAccessToken([]byte(testKey), testIssuer, "user-uuid", testAudience, "session", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := IssueAccessToken([]byte(testKey), testIssuer, "user-uuid", testAudience, "session", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	firstClaims, err := ValidateAccessToken(first, []byte(testKey), testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	secondClaims, err := ValidateAccessToken(second, []byte(testKey), testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	if firstClaims.ID == secondClaims.ID {
		t.Fatalf("jti was reused: %q", firstClaims.ID)
	}
}

func TestValidateAccessTokenRejectsInvalidParameters(t *testing.T) {
	tests := []struct {
		name     string
		issuer   string
		audience string
		key      string
	}{
		{name: "wrong audience", issuer: testIssuer, audience: "other-application", key: testKey},
		{name: "wrong issuer", issuer: "other-provider", audience: testAudience, key: testKey},
		{name: "wrong signing key", issuer: testIssuer, audience: testAudience, key: "another signing key"},
	}

	tokenString, err := IssueAccessToken([]byte(testKey), testIssuer, "user-uuid", testAudience, "session", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ValidateAccessToken(tokenString, []byte(test.key), test.issuer, test.audience); err == nil {
				t.Fatal("expected validation to fail")
			}
		})
	}
}

func TestValidateAccessTokenRejectsExpiredToken(t *testing.T) {
	claims := Claims{
		Scope: DefaultScope,
		SID:   "session",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Subject:   "user-uuid",
			Audience:  jwt.ClaimStrings{testAudience},
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ID:        "expired-token",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(testKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAccessToken(tokenString, []byte(testKey), testIssuer, testAudience); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

func TestValidateAccessTokenRejectsAlgorithmSubstitution(t *testing.T) {
	claims := Claims{
		Scope: DefaultScope,
		SID:   "session",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Subject:   "user-uuid",
			Audience:  jwt.ClaimStrings{testAudience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			ID:        "substituted-algorithm-token",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	tokenString, err := token.SignedString([]byte(testKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAccessToken(tokenString, []byte(testKey), testIssuer, testAudience); err == nil || !strings.Contains(err.Error(), "unexpected signing algorithm") {
		t.Fatalf("expected algorithm rejection, got %v", err)
	}
}
