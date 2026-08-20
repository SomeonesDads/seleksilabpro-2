package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Profile is the identity App A receives from Auth Provider /userinfo. It
// carries no credentials.
type Profile struct {
	Sub              string   `json:"sub"`
	Email            string   `json:"email"`
	Name             string   `json:"name"`
	Groups           []string `json:"groups"`
	CentralSessionID string   `json:"centralSessionId"`
}

// Provider is the back-channel contract App A uses to talk to the Auth
// Provider. It is an interface so handlers can be tested without a live server.
type Provider interface {
	// AuthorizeURL builds the front-channel /authorize redirect the browser
	// follows to start the OAuth authorization-code + PKCE flow.
	AuthorizeURL(state, codeChallenge, redirectURI string) string
	// ExchangeCode performs the server-to-server token exchange.
	ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (accessToken string, err error)
	// FetchProfile calls /userinfo with the access token and returns identity.
	FetchProfile(ctx context.Context, accessToken string) (*Profile, error)
}

type Client struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	HTTP         *http.Client
}

func NewClient(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTP:         &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) AuthorizeURL(state, codeChallenge, redirectURI string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	return c.BaseURL + "/authorize?" + q.Encode()
}

func (c *Client) ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ClientID, c.ClientSecret)

	resp, err := c.http().Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if body.AccessToken == "" {
		return "", errors.New("token endpoint returned empty access token")
	}
	return body.AccessToken, nil
}

func (c *Client) FetchProfile(ctx context.Context, accessToken string) (*Profile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-Client-ID", c.ClientID)
	req.Header.Set("X-Client-Secret", c.ClientSecret)

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned HTTP %d", resp.StatusCode)
	}
	var profile Profile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode userinfo response: %w", err)
	}
	if profile.Sub == "" {
		return nil, errors.New("userinfo returned empty subject")
	}
	// The Auth Provider no longer returns centralSessionId from /userinfo
	// (only sub/email/name/groups per spec). The relying app derives the
	// central session id from the access-token `sid` claim it already holds,
	// which the server validated above.
	profile.CentralSessionID = centralSessionIDFromToken(accessToken)
	return &profile, nil
}

// centralSessionIDFromToken reads the `sid` claim (central session id) from a
// signed access token without verifying the signature. The value is only used
// as a correlation id for SSO revocation; the token itself has already been
// validated by the Auth Provider via the /userinfo call above.
func centralSessionIDFromToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		SID string `json:"sid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.SID
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
