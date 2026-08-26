package agent

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Handler struct {
	service *Service
	cfg     Config
}

func NewHandler(service *Service, cfg Config) http.Handler {
	handler := &Handler{
		service: service,
		cfg:     cfg,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handler.handleHealth)
	mux.Handle("/v1/capabilities", handler.requireBearerAuth(http.HandlerFunc(handler.handleCapabilities)))
	mux.Handle("/v1/operations", handler.requireBearerAuth(http.HandlerFunc(handler.handleOperations)))
	return mux
}

func (h *Handler) requireBearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok || !h.validAuthToken(token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sroiaaa"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"status": "error",
				"error": map[string]string{
					"code":    "unauthorized",
					"message": "missing or invalid bearer token",
				},
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

func (h *Handler) validAuthToken(candidate string) bool {
	for _, expected := range h.cfg.AuthTokens {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"agent":   agentName,
		"version": agentVersion,
	})
}

func (h *Handler) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, h.service.Capabilities())
}

func (h *Handler) handleOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req RequestEnvelope
	if err := h.decodeRequest(w, r, &req); err != nil {
		statusCode := http.StatusBadRequest
		code := "invalid_json"
		message := "request body must contain exactly one valid JSON value"
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			statusCode = http.StatusRequestEntityTooLarge
			code = "request_too_large"
			message = fmt.Sprintf("request body exceeds %d bytes", h.cfg.MaxRequestBytes)
		}
		h.writeRequestError(w, r, req.Operation, statusCode, code, message)
		return
	}

	resp, statusCode := h.service.Execute(r.Context(), req)
	metadata := map[string]any{}
	if req.Operation == "filesystem.read" || req.Operation == "filesystem.tail" ||
		req.Operation == "filesystem.list" || req.Operation == "filesystem.stat" {
		metadata["allowed_roots"] = h.cfg.AllowedRoots
	}
	_ = h.service.auditor.Record(AuditEvent{
		RequestID:  resp.RequestID,
		Operation:  req.Operation,
		Status:     resp.Status,
		DurationMS: resp.Metadata.DurationMS,
		RemoteAddr: r.RemoteAddr,
		Metadata:   metadata,
		Code:       errorCode(resp.Error),
		Message:    errorMessage(resp.Error),
	})
	writeJSON(w, statusCode, resp)
}

func (h *Handler) decodeRequest(w http.ResponseWriter, r *http.Request, req *RequestEnvelope) error {
	body := http.MaxBytesReader(w, r.Body, h.cfg.MaxRequestBytes)
	defer body.Close()

	decoder := json.NewDecoder(body)
	if err := decoder.Decode(req); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body contains multiple JSON values")
		}
		return err
	}
	return nil
}

func (h *Handler) writeRequestError(
	w http.ResponseWriter,
	r *http.Request,
	operation string,
	statusCode int,
	code string,
	message string,
) {
	resp := ResponseEnvelope{
		RequestID: newRequestID(),
		Operation: operation,
		Status:    "error",
		Metadata: ResponseMeta{
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			DurationMS: 0,
			Truncated:  false,
			Agent:      agentName,
			Version:    agentVersion,
		},
		Error: &ErrorPayload{
			Code:    code,
			Message: message,
		},
	}
	writeJSON(w, statusCode, resp)
	_ = h.service.auditor.Record(AuditEvent{
		RequestID:  resp.RequestID,
		Operation:  operation,
		Status:     "error",
		Code:       code,
		Message:    message,
		DurationMS: 0,
		RemoteAddr: r.RemoteAddr,
	})
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func newRequestID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "req_fallback"
	}
	return "req_" + hex.EncodeToString(raw[:])
}

func errorCode(err *ErrorPayload) string {
	if err == nil {
		return ""
	}
	return err.Code
}

func errorMessage(err *ErrorPayload) string {
	if err == nil {
		return ""
	}
	return err.Message
}
