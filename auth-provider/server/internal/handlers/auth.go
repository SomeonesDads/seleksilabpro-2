package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/tokens"
	sharederrors "github.com/SomeonesDads/seleksilabpro-2/shared/errors"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const mfaPendingCookie = "mfa_pending"
const ssoSessionCookie = "sso_session"
const mfaChallengeTTL = 5 * time.Minute
const mfaMaxAttempts = 5

type MFAVerifier func(context.Context, uuid.UUID, string) bool

type AuthHandler struct {
	Users              UserStore
	UserProfiles       UserProfileStore
	MFA                MFAStore
	TOTP               TOTPStore
	Applications       ApplicationStore
	Policies           PolicyStore
	Sessions           SessionStore
	SessionLookup      SessionLookupStore
	SessionRevocation  SessionRevocationStore
	AuthorizationCodes AuthorizationCodeStore
	TokenRedemption    AuthorizationCodeRedemptionStore
	Audit              AuditStore
	AccessTokens       AccessTokenStore
	Groups             GroupStore
	VerifyMFA          MFAVerifier
	Logger             *slog.Logger
	AuthCodeTTL        time.Duration
	AccessTokenTTL     time.Duration
	SessionTTL         time.Duration
	JWTIssuer          string
	JWTSigningKey      []byte
	TokenStrategy      string
}

// GET /login
// Renders (or redirects to) the login page. If a valid central session
// cookie is already present, this may be skipped entirely by /authorize.
func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	intent, err := h.validateLoginIntent(r, r.URL.Query().Get("return_to"))
	if err != nil {
		if !errors.Is(err, errInvalidAuthorization) {
			h.log().Error("login intent validation failed", slog.Any("err", err))
			writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
			return
		}
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid login request")
		return
	}
	renderLoginPage(w, intent)
}

// POST /login
// Body: { "email": "...", "password": "..." }
// Best practiceny kita mau error message yg less useful for attackers. Kaya error check json itu samain kaya dibawahnya
// Steps (see Pengantar > OAuth2 Authorization Code Flow diagram):
//  4. [B01 bonus] If user has MFA enrolled, do NOT create a central session
//     yet — issue a short-lived "MFA pending" state instead and require
//     POST /login/mfa before continuing.
//  5. Generate a random session token (idgen.RandomToken), hash it
//     (idgen.HashToken), INSERT into sso_sessions.
//  6. Set-Cookie with the RAW token (HttpOnly, Secure, SameSite=Lax),
//     never the hash.
//  7. Write an audit_logs row (login success/failed).
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	input, err := decodeLoginInput(r)
	if err != nil {
		h.audit(r, "LoginFailed", "failed", nil, nil, nil, nil)
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid credentials")
		return
	}
	intent, err := h.validateLoginIntent(r, input.ReturnTo)
	if err != nil {
		if !errors.Is(err, errInvalidAuthorization) {
			h.log().Error("login intent validation failed", slog.Any("err", err))
			writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
			return
		}
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid login request")
		return
	}

	if h.Users == nil {
		h.log().Error("user repository is not configured")
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
		return
	}
	user, err := h.Users.FindByEmail(r.Context(), input.Email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			h.audit(r, "LoginFailed", "failed", nil, nil, nil, nil)
			writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid credentials")
			return
		}
		h.log().Error("user lookup failed", slog.Any("err", err))
		h.audit(r, "LoginFailed", "failed", nil, nil, nil, nil)
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
		return
	}
	// 2. Compare password + cek aktif/ga
	if user == nil || !user.IsActive() || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
		if user != nil {
			userID := user.ID
			h.audit(r, "LoginFailed", "failed", &userID, nil, nil, nil)
		} else {
			h.audit(r, "LoginFailed", "failed", nil, nil, nil, nil)
		}
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid credentials")
		return
	}

	if h.TOTP != nil {
		credential, totpErr := h.TOTP.FindByUserID(r.Context(), user.ID)
		if totpErr == nil && credential != nil {
			// Continue below with a short-lived MFA challenge.
		} else if totpErr == nil || errors.Is(totpErr, repository.ErrTOTPNotFound) {
			if err := h.completePasswordLogin(w, r, user.ID, intent); err != nil {
				h.log().Error("session creation failed", slog.Any("err", err))
				userID := user.ID
				h.audit(r, "LoginFailed", "failed", &userID, nil, nil, nil)
				writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
			}
			return
		} else {
			h.log().Error("TOTP lookup failed", slog.Any("err", totpErr))
			userID := user.ID
			h.audit(r, "LoginFailed", "failed", &userID, nil, nil, nil)
			writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
			return
		}
	}
	if h.TOTP == nil {
		if err := h.completePasswordLogin(w, r, user.ID, intent); err != nil {
			h.log().Error("session creation failed", slog.Any("err", err))
			userID := user.ID
			h.audit(r, "LoginFailed", "failed", &userID, nil, nil, nil)
			writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
		}
		return
	}

	// 3. Issue pending MFA token
	rawToken, err := idgen.RandomToken(32)
	if err != nil {
		userID := user.ID
		h.audit(r, "MFAFailed", "failed", &userID, nil, nil, nil)
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
		return
	}
	challenge := models.MFALoginChallenge{
		UserID:    user.ID,
		TokenHash: idgen.HashToken(rawToken),
		ExpiresAt: time.Now().Add(mfaChallengeTTL),
	}
	if h.MFA == nil {
		userID := user.ID
		h.audit(r, "MFAFailed", "failed", &userID, nil, nil, nil)
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
		return
	}
	if err := h.MFA.Create(r.Context(), &challenge); err != nil {
		h.log().Error("MFA challenge creation failed", slog.Any("err", err))
		userID := user.ID
		h.audit(r, "MFAFailed", "failed", &userID, nil, nil, nil)
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
		return
	}
	setAuthCookie(w, mfaPendingCookie, rawToken, mfaChallengeTTL)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"mfa_required": true, "expires_in": int(mfaChallengeTTL.Seconds()), "return_to": intent})
}

// POST /login/mfa
// LoginMFA verifies the pending TOTP challenge and creates the central session.
func (h *AuthHandler) LoginMFA(w http.ResponseWriter, r *http.Request) {
	input, err := decodeMFAInput(r)
	if err != nil {
		h.audit(r, "MFAFailed", "failed", nil, nil, nil, nil)
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid MFA code")
		return
	}
	intent, err := h.validateLoginIntent(r, input.ReturnTo)
	if err != nil {
		if !errors.Is(err, errInvalidAuthorization) {
			h.log().Error("MFA login intent validation failed", slog.Any("err", err))
			writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
			return
		}
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid login request")
		return
	}
	cookie, err := r.Cookie(mfaPendingCookie)
	if err != nil || cookie.Value == "" || h.MFA == nil || h.VerifyMFA == nil {
		h.audit(r, "MFAFailed", "failed", nil, nil, nil, nil)
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid MFA challenge")
		return
	}
	challenge, err := h.MFA.FindActiveByToken(r.Context(), idgen.HashToken(cookie.Value), mfaMaxAttempts)
	if err != nil {
		h.audit(r, "MFAFailed", "failed", nil, nil, nil, nil)
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid MFA challenge")
		return
	}
	claimed, err := h.MFA.ClaimAttempt(r.Context(), challenge.ID, mfaMaxAttempts)
	if err != nil {
		h.log().Error("MFA attempt reservation failed", slog.Any("err", err))
		userID := challenge.UserID
		h.audit(r, "MFAFailed", "failed", &userID, nil, nil, nil)
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
		return
	}
	if !claimed {
		userID := challenge.UserID
		h.audit(r, "MFAFailed", "failed", &userID, nil, nil, nil)
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid MFA challenge")
		return
	}
	if input.Code == "" || !h.VerifyMFA(r.Context(), challenge.UserID, input.Code) {
		userID := challenge.UserID
		h.audit(r, "MFAFailed", "failed", &userID, nil, nil, nil)
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid MFA code")
		return
	}
	rawSessionToken, err := idgen.RandomToken(32)
	if err != nil {
		userID := challenge.UserID
		h.audit(r, "MFAFailed", "failed", &userID, nil, nil, nil)
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
		return
	}
	session := &models.SSOSession{
		UserID:           challenge.UserID,
		SessionTokenHash: idgen.HashToken(rawSessionToken),
		Status:           "active",
		ExpiresAt:        time.Now().Add(h.sessionTTL()),
		IPAddress:        stringPtr(r.RemoteAddr),
		UserAgent:        stringPtr(r.UserAgent()),
	}
	if err := h.MFA.ConsumeAndCreateSession(r.Context(), challenge.ID, session, mfaMaxAttempts); err != nil {
		if !errors.Is(err, repository.ErrMFAChallengeNotFound) {
			h.log().Error("MFA session creation failed", slog.Any("err", err))
			writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authentication unavailable")
			return
		}
		userID := challenge.UserID
		h.audit(r, "MFAFailed", "failed", &userID, nil, nil, nil)
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid MFA challenge")
		return
	}
	clearAuthCookie(w, mfaPendingCookie)
	setAuthCookie(w, ssoSessionCookie, rawSessionToken, h.sessionTTL())
	userID := challenge.UserID
	sessionID := session.ID
	h.audit(r, "MFASucceeded", "success", &userID, nil, &sessionID, nil)
	h.audit(r, "LoginSucceeded", "success", &userID, nil, &sessionID, nil)
	if intent != "" {
		http.Redirect(w, r, intent, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "mfa_verified": true})
}

func (h *AuthHandler) completePasswordLogin(w http.ResponseWriter, r *http.Request, userID uuid.UUID, intent string) error {
	session, rawToken, err := h.createSession(r, userID)
	if err != nil {
		return err
	}
	setAuthCookie(w, ssoSessionCookie, rawToken, h.sessionTTL())
	sessionID := session.ID
	h.audit(r, "LoginSucceeded", "success", &userID, nil, &sessionID, nil)
	if intent != "" {
		http.Redirect(w, r, intent, http.StatusFound)
		return nil
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "mfa_required": false})
}

func (h *AuthHandler) createSession(r *http.Request, userID uuid.UUID) (*models.SSOSession, string, error) {
	if h.Sessions == nil {
		return nil, "", errors.New("session repository is not configured")
	}
	rawToken, err := idgen.RandomToken(32)
	if err != nil {
		return nil, "", err
	}
	session := &models.SSOSession{UserID: userID, SessionTokenHash: idgen.HashToken(rawToken), Status: "active", ExpiresAt: time.Now().Add(h.sessionTTL()), IPAddress: stringPtr(r.RemoteAddr), UserAgent: stringPtr(r.UserAgent())}
	if err := h.Sessions.Create(r.Context(), session); err != nil {
		return nil, "", err
	}
	return session, rawToken, nil
}

func stringPtr(value string) *string { return &value }

func (h *AuthHandler) log() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h *AuthHandler) sessionTTL() time.Duration {
	if h.SessionTTL > 0 {
		return h.SessionTTL
	}
	return defaultSessionTTL
}

func (h *AuthHandler) authCodeTTL() time.Duration {
	if h.AuthCodeTTL > 0 {
		return h.AuthCodeTTL
	}
	return defaultAuthCodeTTL
}

func (h *AuthHandler) accessTokenTTL() time.Duration {
	if h.AccessTokenTTL > 0 {
		return h.AccessTokenTTL
	}
	return defaultAccessTokenTTL
}

func (h *AuthHandler) jwtIssuer() string {
	if h.JWTIssuer != "" {
		return h.JWTIssuer
	}
	return defaultJWTIssuer
}

func (h *AuthHandler) tokenStrategy() string {
	if h.TokenStrategy != "" {
		return h.TokenStrategy
	}
	return defaultTokenStrategy
}

func (h *AuthHandler) userProfiles() UserProfileStore {
	if h.UserProfiles != nil {
		return h.UserProfiles
	}
	store, _ := h.Users.(UserProfileStore)
	return store
}

func (h *AuthHandler) sessionLookup() SessionLookupStore {
	if h.SessionLookup != nil {
		return h.SessionLookup
	}
	store, _ := h.Sessions.(SessionLookupStore)
	return store
}

func (h *AuthHandler) sessionRevocation() SessionRevocationStore {
	if h.SessionRevocation != nil {
		return h.SessionRevocation
	}
	store, _ := h.Sessions.(SessionRevocationStore)
	return store
}

// GET /authorize?client_id=...&redirect_uri=...&state=...&code_challenge=...&code_challenge_method=S256
//
// Steps (see "Evaluasi Group Policy" in the spec):
//  1. Look up application by client_id; reject if missing or status != active.
//  2. Validate redirect_uri is an EXACT match against
//     application_redirect_uris (no prefix matching — open redirect risk).
//  3. Check for a valid central session cookie.
//     - If absent/invalid: redirect to /login, preserving all query params
//     (typically via a short-lived "login intent" state) so the flow can
//     resume after credentials are submitted.
//  4. Evaluate policy: user active AND user's groups intersect with
//     application_group_policies (effect=allow) for this application.
//     - On deny: record PolicyDenied in audit_logs, return an error
//     (redirect to redirect_uri with an error param, or a safe error
//     page — do NOT redirect to an unvalidated URI).
//  5. On allow: generate authorization code, hash it, INSERT into
//     authorization_codes with the redirect_uri, code_challenge,
//     code_challenge_method, short TTL (2-5 min per spec).
//  6. 302 redirect to redirect_uri?code=...&state=...
func (h *AuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	req, app, err := h.validateAuthorizeRequest(r)
	if err != nil {
		if errors.Is(err, errInvalidAuthorization) {
			writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "authorization request invalid")
			return
		}
		h.log().Error("authorization validation failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authorization unavailable")
		return
	}

	cookie, cookieErr := r.Cookie(ssoSessionCookie)
	if cookieErr != nil || cookie.Value == "" {
		http.Redirect(w, r, loginRedirectTarget(r.URL.RequestURI()), http.StatusFound)
		return
	}
	sessions := h.sessionLookup()
	if sessions == nil {
		h.log().Error("session repository is not configured")
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authorization unavailable")
		return
	}
	session, err := sessions.FindActiveByTokenHash(r.Context(), idgen.HashToken(cookie.Value))
	if err != nil {
		if errors.Is(err, repository.ErrSessionNotFound) {
			http.Redirect(w, r, loginRedirectTarget(r.URL.RequestURI()), http.StatusFound)
			return
		}
		h.log().Error("session lookup failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authorization unavailable")
		return
	}
	if session == nil {
		http.Redirect(w, r, loginRedirectTarget(r.URL.RequestURI()), http.StatusFound)
		return
	}
	profiles := h.userProfiles()
	if profiles == nil || h.Policies == nil || h.AuthorizationCodes == nil {
		h.log().Error("authorization repositories are not configured")
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authorization unavailable")
		return
	}
	user, err := profiles.FindByID(r.Context(), session.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			h.audit(r, "PolicyDenied", "failed", nil, &app.ID, &session.ID, nil)
			writeError(w, r, http.StatusForbidden, sharederrors.CodeAccessDenied, "access denied")
			return
		}
		h.log().Error("authorization user lookup failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authorization unavailable")
		return
	}
	if user == nil || !user.IsActive() {
		if user != nil {
			h.audit(r, "PolicyDenied", "failed", &user.ID, &app.ID, &session.ID, nil)
		} else {
			h.audit(r, "PolicyDenied", "failed", nil, &app.ID, &session.ID, nil)
		}
		if user != nil && !user.IsActive() {
			http.Redirect(w, r, loginRedirectTarget(r.URL.RequestURI()), http.StatusFound)
			return
		}
		redirectOAuthError(w, r, req.RedirectURI, req.State, "access_denied")
		return
	}
	allowed, err := h.Policies.UserHasApplicationAccess(r.Context(), user.ID, app.ID)
	if err != nil {
		h.log().Error("policy lookup failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authorization unavailable")
		return
	}
	if !allowed {
		h.audit(r, "PolicyDenied", "failed", &user.ID, &app.ID, &session.ID, nil)
		redirectOAuthError(w, r, req.RedirectURI, req.State, "access_denied")
		return
	}

	target, err := url.Parse(req.RedirectURI)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "authorization request invalid")
		return
	}
	now := time.Now()
	rawCode, err := idgen.RandomToken(32)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authorization unavailable")
		return
	}
	code := &models.AuthorizationCode{
		CodeHash:            idgen.HashToken(rawCode),
		UserID:              user.ID,
		ApplicationID:       app.ID,
		SSOSessionID:        session.ID,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		CreatedAt:           now,
		ExpiresAt:           now.Add(h.authCodeTTL()),
	}
	if err := h.AuthorizationCodes.Create(r.Context(), code); err != nil {
		h.log().Error("authorization code creation failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "authorization unavailable")
		return
	}
	h.audit(r, "AuthorizationCodeIssued", "success", &user.ID, &app.ID, &session.ID, nil)
	query := target.Query()
	query.Set("code", rawCode)
	query.Set("state", req.State)
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// POST /token   (back-channel, server-to-server — App A/B backend calls this)
// Body (JSON or application/x-www-form-urlencoded):
// { "grant_type": "authorization_code", "code": "...",
//
//	"redirect_uri": "...", "client_id": "...", "client_secret": "...",
//	"code_verifier": "..." }
//
// Confidential clients may send credentials with HTTP Basic authentication.
//
// Steps:
//  1. Authenticate the client (client_id + client_secret, if confidential).
//  2. Hash the incoming code, look up authorization_codes by code_hash.
//  3. Reject if: not found, expired, already used (used_at IS NOT NULL),
//     application_id mismatch, redirect_uri mismatch, or the owning
//     sso_session is no longer valid.
//  4. Verify PKCE: idgen.PKCEChallengeS256(code_verifier) ==
//     stored code_challenge.
//  5. Issue the JWT and atomically consume the code while inserting token
//     metadata. The repository must roll back both writes on failure.
//  6. Return { "access_token": "...", "token_type": "Bearer", "expires_in": ... }.
func (h *AuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	input, err := decodeTokenInput(r)
	if err != nil || input.GrantType != "authorization_code" || input.Code == "" || input.RedirectURI == "" || input.CodeVerifier == "" {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidGrant, "authorization grant invalid")
		return
	}
	clientID, clientSecret, credentialsOK := tokenClientCredentials(r, input)
	if !credentialsOK {
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeInvalidClient, "client authentication failed")
		return
	}
	app, err := h.findClient(r, clientID, clientSecret)
	if err != nil {
		if errors.Is(err, errInvalidClient) {
			writeError(w, r, http.StatusUnauthorized, sharederrors.CodeInvalidClient, "client authentication failed")
			return
		}
		h.log().Error("client lookup failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
		return
	}
	if h.AuthorizationCodes == nil || h.TokenRedemption == nil || h.sessionLookup() == nil || h.userProfiles() == nil {
		h.log().Error("token repositories are not configured")
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
		return
	}
	code, err := h.AuthorizationCodes.FindByHash(r.Context(), idgen.HashToken(input.Code))
	if err != nil {
		if !errors.Is(err, repository.ErrAuthorizationCodeNotFound) {
			h.log().Error("authorization code lookup failed", slog.Any("err", err))
			writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
			return
		}
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidGrant, "authorization grant invalid")
		return
	}
	if code == nil || code.UsedAt != nil || !time.Now().Before(code.ExpiresAt) || code.ApplicationID != app.ID || code.RedirectURI != input.RedirectURI || code.CodeChallengeMethod != "S256" || !validS256Challenge(code.CodeChallenge) || !equalPKCE(code.CodeChallenge, input.CodeVerifier) {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidGrant, "authorization grant invalid")
		return
	}
	session, err := h.sessionLookup().FindActiveByID(r.Context(), code.SSOSessionID)
	if err != nil {
		if !errors.Is(err, repository.ErrSessionNotFound) {
			h.log().Error("authorization session lookup failed", slog.Any("err", err))
			writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
			return
		}
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidGrant, "authorization grant invalid")
		return
	}
	user, err := h.userProfiles().FindByID(r.Context(), code.UserID)
	if err != nil {
		if !errors.Is(err, repository.ErrUserNotFound) {
			h.log().Error("authorization user lookup failed", slog.Any("err", err))
			writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
			return
		}
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidGrant, "authorization grant invalid")
		return
	}
	if session == nil || user == nil || !user.IsActive() || session.UserID != user.ID {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidGrant, "authorization grant invalid")
		return
	}
	if h.tokenStrategy() != "jwt" || len(h.JWTSigningKey) == 0 {
		h.log().Error("unsupported token configuration")
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
		return
	}
	accessToken, err := tokens.IssueAccessToken(h.JWTSigningKey, h.jwtIssuer(), user.ID.String(), app.ID.String(), session.ID.String(), h.accessTokenTTL())
	if err != nil {
		h.log().Error("access token creation failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
		return
	}
	claims, err := tokens.ValidateAccessToken(accessToken, h.JWTSigningKey, h.jwtIssuer(), app.ID.String())
	if err != nil {
		h.log().Error("access token validation failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
		return
	}
	jti, err := uuid.Parse(claims.ID)
	if err != nil {
		h.log().Error("access token jti invalid", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
		return
	}
	if claims.ExpiresAt == nil {
		h.log().Error("access token expiry claim missing")
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
		return
	}
	metadata := &models.AccessToken{JTI: jti, UserID: user.ID, ApplicationID: app.ID, SessionID: session.ID, ExpiresAt: claims.ExpiresAt.Time}
	if err := h.TokenRedemption.Redeem(r.Context(), code.ID, metadata); err != nil {
		if errors.Is(err, repository.ErrAuthorizationCodeNotFound) {
			writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidGrant, "authorization grant invalid")
			return
		}
		h.log().Error("authorization code redemption failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "token service unavailable")
		return
	}
	h.audit(r, "TokenIssued", "success", &user.ID, &app.ID, &session.ID, nil)
	_ = writeJSON(w, http.StatusOK, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": int(h.accessTokenTTL().Seconds())})
}

// GET /userinfo   (back-channel, Authorization: Bearer <access_token>)
//
// Validate the token (hash lookup or JWT signature verification depending
// on strategy), confirm not expired/revoked, confirm audience ==
// requesting application_id (an App A token must never validate for App B).
// Return { "sub": userId, "email": ..., "name": ..., "groups": [...] }.
func (h *AuthHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	accessToken, ok := bearerToken(r)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "authentication required")
		return
	}
	clientID, clientSecret := clientCredentials(r)
	if clientID == "" {
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "application authentication required")
		return
	}
	app, err := h.findClient(r, clientID, clientSecret)
	if err != nil {
		if errors.Is(err, errInvalidClient) {
			writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "application authentication failed")
			return
		}
		h.log().Error("userinfo client lookup failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "user information unavailable")
		return
	}
	if h.tokenStrategy() != "jwt" || len(h.JWTSigningKey) == 0 {
		h.log().Error("unsupported token configuration")
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "user information unavailable")
		return
	}
	claims, err := tokens.ValidateAccessToken(accessToken, h.JWTSigningKey, h.jwtIssuer(), app.ID.String())
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid access token")
		return
	}
	jti, jtiErr := uuid.Parse(claims.ID)
	sessionID, sessionErr := uuid.Parse(claims.SID)
	userID, userErr := uuid.Parse(claims.Subject)
	if claims.Scope != tokens.DefaultScope || jtiErr != nil || sessionErr != nil || userErr != nil || h.AccessTokens == nil || h.sessionLookup() == nil || h.userProfiles() == nil || h.Groups == nil {
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid access token")
		return
	}
	metadata, err := h.AccessTokens.FindActiveByJTI(r.Context(), jti)
	if err != nil {
		if errors.Is(err, repository.ErrAccessTokenNotFound) {
			writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid access token")
			return
		}
		h.log().Error("userinfo access-token lookup failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "user information unavailable")
		return
	}
	if metadata == nil || metadata.JTI != jti || metadata.ApplicationID != app.ID || metadata.SessionID != sessionID || metadata.UserID != userID || metadata.RevokedAt != nil || metadata.ExpiresAt.IsZero() || !time.Now().Before(metadata.ExpiresAt) {
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid access token")
		return
	}
	activeSession, err := h.sessionLookup().FindActiveByID(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, repository.ErrSessionNotFound) {
			writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid access token")
			return
		}
		h.log().Error("userinfo session lookup failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "user information unavailable")
		return
	}
	if activeSession == nil || activeSession.UserID != userID || !activeSession.IsValid(time.Now()) {
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid access token")
		return
	}
	user, err := h.userProfiles().FindByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid access token")
			return
		}
		h.log().Error("userinfo user lookup failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "user information unavailable")
		return
	}
	if user == nil || user.ID != userID || !user.IsActive() {
		writeError(w, r, http.StatusUnauthorized, sharederrors.CodeUnauthorized, "invalid access token")
		return
	}
	groups, err := h.Groups.FindByUserID(r.Context(), userID)
	if err != nil {
		h.log().Error("userinfo group lookup failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "user information unavailable")
		return
	}
	groupNames := make([]string, 0, len(groups))
	for _, group := range groups {
		groupNames = append(groupNames, group.Name)
	}
	_ = writeJSON(w, http.StatusOK, map[string]any{"sub": user.ID.String(), "email": user.Email, "name": user.Name, "groups": groupNames})
}

// POST /logout   (SSO / global logout, triggered from the Auth Portal UI)
//
// Steps:
//  1. Resolve the central session from the cookie.
//  2. Revoke it synchronously: UPDATE sso_sessions SET status='revoked',
//     revoked_at=now(), revoke_reason='sso_logout'.
//  3. In the SAME transaction, INSERT an `events` row
//     (event_type=SessionRevoked, application_id=NULL to mean "all apps
//     this user has sessions with") — this is the transactional outbox
//     write. Do not publish to the queue directly from here.
//  4. Clear the central session cookie.
//  5. Return 200 immediately — do NOT wait for App A/B to actually log out.
//     The outbox publisher + Sync Worker handle propagation asynchronously.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(ssoSessionCookie)
	if err != nil || cookie.Value == "" {
		clearAuthCookie(w, ssoSessionCookie)
		h.audit(r, "Logout", "success", nil, nil, nil, nil)
		_ = writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
		return
	}
	if h.sessionLookup() == nil || h.sessionRevocation() == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "logout unavailable")
		return
	}
	session, err := h.sessionLookup().FindActiveByTokenHash(r.Context(), idgen.HashToken(cookie.Value))
	if err != nil {
		if errors.Is(err, repository.ErrSessionNotFound) {
			clearAuthCookie(w, ssoSessionCookie)
			h.audit(r, "Logout", "success", nil, nil, nil, nil)
			_ = writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
			return
		}
		h.log().Error("logout session lookup failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "logout unavailable")
		return
	}
	if session == nil {
		clearAuthCookie(w, ssoSessionCookie)
		h.audit(r, "Logout", "success", nil, nil, nil, nil)
		_ = writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
		return
	}
	if err := h.sessionRevocation().RevokeAndCreateEvent(r.Context(), session.ID, "sso_logout"); err != nil && !errors.Is(err, repository.ErrSessionNotFound) {
		h.log().Error("logout revocation failed", slog.Any("err", err))
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "logout unavailable")
		return
	}
	clearAuthCookie(w, ssoSessionCookie)
	h.audit(r, "Logout", "success", &session.UserID, nil, &session.ID, nil)
	_ = writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
}
