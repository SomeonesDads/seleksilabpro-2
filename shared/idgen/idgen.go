// Package idgen centralizing generation cryptographically random values: session tokens, authorization codes, PKCE code_verifiers
package idgen

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// RandomToken returns a URL-safe, base64-encoded random string with
// nBytes of entropy (32 is a reasonable default for session/opaque tokens).
// This is the RAW value — it goes in the cookie / is handed to the client.
// Only its hash (see HashToken) should ever be persisted to the DB, per
// the spec's requirement that sensitive values are stored hashed.
func RandomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("idgen: reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken produces a deterministic SHA-256 hex digest of a raw token,
// suitable for storing in *_hash columns (session_token_hash, code_hash,
// token_hash) and for equality-lookup at validation time.
//
// NOTE: this is fine for high-entropy random tokens (session ids, auth
// codes) where brute force isn't a concern. It is NOT appropriate for
// user passwords — use bcrypt/argon2 for password_hash instead.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// PKCEChallengeS256 computes the S256 code_challenge for a given
// code_verifier per RFC 7636: BASE64URL(SHA256(code_verifier)).
func PKCEChallengeS256(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
