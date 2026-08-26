package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
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
	mux.HandleFunc("/v1/capabilities", handler.handleCapabilities)
	mux.HandleFunc("/v1/operations", handler.handleOperations)
	return mux
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp := ResponseEnvelope{
			RequestID: newRequestID(),
			Operation: "",
			Status:    "error",
			Metadata: ResponseMeta{
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
				DurationMS: 0,
				Truncated:  false,
				Agent:      agentName,
				Version:    agentVersion,
			},
			Error: &ErrorPayload{
				Code:    "invalid_json",
				Message: "request body must be valid JSON",
			},
		}
		writeJSON(w, http.StatusBadRequest, resp)
		_ = h.service.auditor.Record(AuditEvent{
			RequestID:  resp.RequestID,
			Operation:  req.Operation,
			Status:     "error",
			Code:       "invalid_json",
			Message:    "request body must be valid JSON",
			DurationMS: 0,
			RemoteAddr: r.RemoteAddr,
		})
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
