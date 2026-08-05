// Format Error Standar:
//
//	{
//	  "error": {
//	    "code": "INVALID_GRANT",
//	    "message": "Authorization request tidak valid",
//	    "requestId": "uuid"
//	  }
//	}
//
// Responses gak boleh leak klo email udh registered, password
// hashes, stack traces, tokens, & detail internal policy.
// sensitive info di server log aj.
package errors

import (
	"encoding/json"
	"net/http"
)

// Error code
const (
	CodeInvalidRequest     = "INVALID_REQUEST"
	CodeInvalidGrant       = "INVALID_GRANT"  // bad/expired/used auth code, bad PKCE verifier
	CodeInvalidClient      = "INVALID_CLIENT" // unknown client_id / bad client_secret
	CodeUnauthorized       = "UNAUTHORIZED"   // not authenticated
	CodeAccessDenied       = "ACCESS_DENIED"  // policy evaluation failed
	CodeNotFound           = "NOT_FOUND"
	CodeConflict           = "CONFLICT"
	CodeInternal           = "INTERNAL_ERROR"
	CodeInvalidRedirectURI = "INVALID_REDIRECT_URI"
)

type APIError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
}

type envelope struct {
	Error APIError `json:"error"`
}

// package error message ke HTTP.
// requestID dari request-scoped correlation ID (di shared/logging)
// jadi gampang cross-reference ke logs.
func Write(w http.ResponseWriter, status int, code, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Error: APIError{
		Code:      code,
		Message:   message,
		RequestID: requestID,
	}})
}
