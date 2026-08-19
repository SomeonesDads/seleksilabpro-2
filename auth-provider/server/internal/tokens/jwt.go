// Package tokens defines the access-token contract used by the Auth Provider.
package tokens

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	SigningAlgorithm = "HS256"
	DefaultIssuer    = "auth-provider"
	DefaultScope     = "userinfo"
	DefaultTTL       = 15 * time.Minute
)

// Claims is the complete access-token claim set. Do not add secrets or raw
// credentials to this type: access tokens are sent to relying applications.
type Claims struct {
	Scope string `json:"scope"`
	SID   string `json:"sid"`
	jwt.RegisteredClaims
}

// IssueAccessToken creates an HS256 access token for one application.
func IssueAccessToken(signingKey []byte, issuer, subject, audience, sessionID string, ttl time.Duration) (string, error) {
	if len(signingKey) == 0 {
		return "", errors.New("tokens: signing key is required")
	}
	if issuer == "" {
		issuer = DefaultIssuer
	}
	if subject == "" || audience == "" || sessionID == "" {
		return "", errors.New("tokens: subject, audience, and session ID are required")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	now := time.Now()
	claims := Claims{
		Scope: DefaultScope,
		SID:   sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

// ValidateAccessToken verifies the signature, exact algorithm, issuer,
// audience, and required expiration claim before returning the claims.
func ValidateAccessToken(tokenString string, signingKey []byte, issuer, audience string) (*Claims, error) {
	if strings.TrimSpace(tokenString) == "" {
		return nil, errors.New("tokens: token is required")
	}
	if len(signingKey) == 0 {
		return nil, errors.New("tokens: signing key is required")
	}
	if issuer == "" {
		issuer = DefaultIssuer
	}
	if audience == "" {
		return nil, errors.New("tokens: audience is required")
	}

	var claims Claims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != SigningAlgorithm || token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("tokens: unexpected signing algorithm %q", token.Method.Alg())
		}
		return signingKey, nil
	}, jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	if token == nil || !token.Valid {
		return nil, errors.New("tokens: token is invalid")
	}
	if claims.ID == "" {
		return nil, errors.New("tokens: jti is required")
	}
	if claims.Subject == "" {
		return nil, errors.New("tokens: subject is required")
	}
	if claims.SID == "" {
		return nil, errors.New("tokens: sid is required")
	}
	return &claims, nil
}
