package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Auditor struct {
	mu   sync.Mutex
	file *os.File
}

type AuditEvent struct {
	Timestamp  string         `json:"timestamp"`
	RequestID  string         `json:"request_id"`
	Operation  string         `json:"operation"`
	Status     string         `json:"status"`
	Code       string         `json:"code,omitempty"`
	Message    string         `json:"message,omitempty"`
	DurationMS int64          `json:"duration_ms"`
	RemoteAddr string         `json:"remote_addr,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

func NewAuditor(path string) (*Auditor, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &Auditor{file: file}, nil
}

func (a *Auditor) Record(event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = a.file.Write(append(encoded, '\n'))
	return err
}
