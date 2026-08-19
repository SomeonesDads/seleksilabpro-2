package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
)

var (
	errInvalidAuthorization = errors.New("invalid authorization request")
	errInvalidClient        = errors.New("invalid client")
)

type authorizeRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type loginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	ReturnTo string `json:"return_to"`
}

type mfaInput struct {
	Code     string `json:"code"`
	ReturnTo string `json:"return_to"`
}

func decodeLoginInput(r *http.Request) (loginInput, error) {
	var input loginInput
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return input, decodeJSONBody(r, &input)
	}
	if err := r.ParseForm(); err != nil {
		return input, err
	}
	input.Email = r.FormValue("email")
	input.Password = r.FormValue("password")
	input.ReturnTo = r.FormValue("return_to")
	return input, nil
}

func decodeMFAInput(r *http.Request) (mfaInput, error) {
	var input mfaInput
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return input, decodeJSONBody(r, &input)
	}
	if err := r.ParseForm(); err != nil {
		return input, err
	}
	input.Code = r.FormValue("code")
	input.ReturnTo = r.FormValue("return_to")
	return input, nil
}

func (h *AuthHandler) validateAuthorizeRequest(r *http.Request) (authorizeRequest, *models.Application, error) {
	query := r.URL.Query()
	req := authorizeRequest{
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		State:               query.Get("state"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
	}
	if query.Get("response_type") != "code" || req.ClientID == "" || req.RedirectURI == "" || req.State == "" || req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return authorizeRequest{}, nil, errInvalidAuthorization
	}
	if h.Applications == nil {
		return authorizeRequest{}, nil, errors.New("application repository is not configured")
	}
	app, err := h.Applications.FindByClientID(r.Context(), req.ClientID)
	if err != nil {
		if errors.Is(err, repository.ErrApplicationNotFound) {
			return authorizeRequest{}, nil, errInvalidAuthorization
		}
		return authorizeRequest{}, nil, err
	}
	if app == nil || !app.IsActive() {
		return authorizeRequest{}, nil, errInvalidAuthorization
	}
	exact, err := h.Applications.HasExactRedirectURI(r.Context(), app.ID, req.RedirectURI)
	if err != nil {
		return authorizeRequest{}, nil, err
	}
	if !exact {
		return authorizeRequest{}, nil, errInvalidAuthorization
	}
	return req, app, nil
}

func safeLoginIntent(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path != "/authorize" {
		return "", false
	}
	query := u.Query()
	if query.Get("response_type") == "" || query.Get("client_id") == "" || query.Get("redirect_uri") == "" {
		return "", false
	}
	return u.RequestURI(), true
}

func loginRedirectTarget(requestURI string) string {
	return "/login?" + url.Values{"return_to": []string{requestURI}}.Encode()
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, sharederrorsCode(code), "authorization request invalid")
		return
	}
	query := target.Query()
	query.Set("error", code)
	if state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// sharederrorsCode keeps OAuth redirect handling independent from response
// rendering while still returning a stable envelope when the URI is unusable.
func sharederrorsCode(code string) string {
	if code == "access_denied" {
		return "ACCESS_DENIED"
	}
	return "INVALID_REQUEST"
}

func renderLoginPage(w http.ResponseWriter, intent string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><body><h1>Sign in</h1><form method="post" action="/login"><input type="hidden" name="return_to" value="%s"><label>Email <input name="email" type="email" required></label><label>Password <input name="password" type="password" required></label><button type="submit">Sign in</button></form></body></html>`, html.EscapeString(intent))
}

func decodeJSONBody(r *http.Request, dst any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body contains multiple values")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(value)
}

func (h *AuthHandler) findClient(r *http.Request, clientID, clientSecret string) (*models.Application, error) {
	if h.Applications == nil {
		return nil, errors.New("application repository is not configured")
	}
	app, err := h.Applications.FindByClientID(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, repository.ErrApplicationNotFound) {
			return nil, errInvalidClient
		}
		return nil, err
	}
	if app == nil || !app.IsActive() {
		return nil, errInvalidClient
	}
	if app.ClientSecretHash != nil {
		if clientSecret == "" {
			return nil, errInvalidClient
		}
		valid, err := h.Applications.VerifyClientSecret(r.Context(), clientID, clientSecret)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, errInvalidClient
		}
	}
	return app, nil
}

func clientCredentials(r *http.Request) (string, string) {
	if clientID := r.Header.Get("X-Client-ID"); clientID != "" {
		return clientID, r.Header.Get("X-Client-Secret")
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if ok {
		return clientID, clientSecret
	}
	return "", ""
}

func equalPKCE(expected, verifier string) bool {
	actual := idgen.PKCEChallengeS256(verifier)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func bearerToken(r *http.Request) (string, bool) {
	value := r.Header.Get("Authorization")
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}
