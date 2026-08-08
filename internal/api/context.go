package api

import (
	"context"
	"encoding/json"
	"net/http"
)

type ctxKey int

const requestIDKey ctxKey = iota

func withRequestID(ctx context.Context, rid string) context.Context {
	return context.WithValue(ctx, requestIDKey, rid)
}

// errorResponse: a single HTTP error type exposed to the client
// ({"error": "generic message"}), never a raw err.Error() from an internal
// package (cf task 05, errors section). Detail goes to the logger, not the
// client.
type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
