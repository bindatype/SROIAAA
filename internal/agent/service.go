package agent

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	agentName    = "sroiaaa-agent"
	agentVersion = "0.1.0"
)

type Service struct {
	cfg     Config
	auditor *Auditor
}

func NewService(cfg Config, auditor *Auditor) *Service {
	cfg.AllowedRoots = canonicalizeRoots(cfg.AllowedRoots)
	return &Service{cfg: cfg, auditor: auditor}
}

func (s *Service) Capabilities() CapabilitiesResponse {
	return CapabilitiesResponse{
		Operations: []OperationCapability{
			{Name: "capabilities.describe", Description: "Describe supported operations and limits."},
			{Name: "host.info", Description: "Return basic host and runtime information."},
			{Name: "filesystem.list", Description: "List entries in an allowlisted directory.", TargetKinds: []string{"directory"}},
			{Name: "filesystem.stat", Description: "Return metadata for an allowlisted path.", TargetKinds: []string{"file", "directory"}},
			{Name: "filesystem.read", Description: "Read a bounded byte range from an allowlisted file.", TargetKinds: []string{"file"}},
			{Name: "filesystem.tail", Description: "Return the trailing bytes from an allowlisted file.", TargetKinds: []string{"file"}},
			{Name: "process.list", Description: "List processes from procfs with bounded fan-out."},
		},
		Limits: map[string]any{
			"allowed_roots":       s.cfg.AllowedRoots,
			"max_read_bytes":      s.cfg.MaxReadBytes,
			"max_tail_bytes":      s.cfg.MaxTailBytes,
			"max_list_entries":    s.cfg.MaxListEntries,
			"max_process_entries": s.cfg.MaxProcessEntries,
		},
	}
}

func (s *Service) Execute(ctx context.Context, req RequestEnvelope) (ResponseEnvelope, int) {
	start := time.Now().UTC()
	requestID := req.RequestID
	if requestID == "" {
		requestID = newRequestID()
	}

	resp := ResponseEnvelope{
		RequestID: requestID,
		Operation: req.Operation,
		Status:    "ok",
		Metadata: ResponseMeta{
			Timestamp: start.Format(time.RFC3339Nano),
			Agent:     agentName,
			Version:   agentVersion,
		},
	}

	var (
		data      any
		truncated bool
		apiErr    *APIError
	)

	switch req.Operation {
	case "capabilities.describe":
		data = s.Capabilities()
	case "host.info":
		data, truncated, apiErr = s.hostInfo()
	case "filesystem.list":
		data, truncated, apiErr = s.filesystemList(req)
	case "filesystem.stat":
		data, truncated, apiErr = s.filesystemStat(req)
	case "filesystem.read":
		data, truncated, apiErr = s.filesystemRead(req)
	case "filesystem.tail":
		data, truncated, apiErr = s.filesystemTail(req)
	case "process.list":
		data, truncated, apiErr = s.processList()
	default:
		apiErr = newAPIError(400, "unknown_operation", "operation is not supported")
	}

	resp.Metadata.DurationMS = time.Since(start).Milliseconds()
	resp.Metadata.Truncated = truncated

	if apiErr != nil {
		resp.Status = "error"
		resp.Error = &ErrorPayload{
			Code:    apiErr.Code,
			Message: apiErr.Message,
		}
		return resp, apiErr.HTTPStatus
	}

	resp.Data = data
	return resp, 200
}

type pathTarget struct {
	Path string `json:"path"`
}

type listParams struct {
	MaxEntries int `json:"max_entries"`
}

type readParams struct {
	Offset   int64 `json:"offset"`
	MaxBytes int64 `json:"max_bytes"`
}

type processRecord struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Cmdline string `json:"cmdline"`
}

func (s *Service) hostInfo() (any, bool, *APIError) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, false, newAPIError(500, "host_info_failed", "could not determine hostname")
	}

	info := map[string]any{
		"hostname": hostname,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"cpus":     runtime.NumCPU(),
		"pid":      os.Getpid(),
	}
	if uptime, ok := readProcUptime(s.cfg.ProcRoot); ok {
		info["uptime_seconds"] = uptime
	}
	if version, ok := readTrimmedFile(filepath.Join(s.cfg.ProcRoot, "version")); ok {
		info["kernel_version"] = version
	}
	if release, ok := readTrimmedFile("/etc/os-release"); ok {
		info["os_release_raw"] = release
	}
	return info, false, nil
}

func (s *Service) filesystemList(req RequestEnvelope) (any, bool, *APIError) {
	target, params, apiErr := s.decodePathAndList(req)
	if apiErr != nil {
		return nil, false, apiErr
	}
	resolved, apiErr := s.resolveAllowedPath(target.Path)
	if apiErr != nil {
		return nil, false, apiErr
	}

	entries, err := os.ReadDir(resolved)
	if err != nil {
		if os.IsPermission(err) {
			return nil, false, newAPIError(403, "permission_denied", "could not read directory")
		}
		return nil, false, newAPIError(500, "list_failed", "could not read directory")
	}

	maxEntries := params.MaxEntries
	if maxEntries <= 0 || maxEntries > s.cfg.MaxListEntries {
		maxEntries = s.cfg.MaxListEntries
	}
	truncated := len(entries) > maxEntries
	entries = entries[:minInt(len(entries), maxEntries)]

	result := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		record := map[string]any{
			"name":     entry.Name(),
			"path":     filepath.Join(resolved, entry.Name()),
			"mode":     info.Mode().String(),
			"size":     info.Size(),
			"mod_time": info.ModTime().UTC().Format(time.RFC3339Nano),
			"type":     fileType(info.Mode()),
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			if link, err := os.Readlink(filepath.Join(resolved, entry.Name())); err == nil {
				record["symlink_target"] = link
			}
		}
		result = append(result, record)
	}

	return map[string]any{
		"path":    resolved,
		"entries": result,
	}, truncated, nil
}

func (s *Service) filesystemStat(req RequestEnvelope) (any, bool, *APIError) {
	var target pathTarget
	if err := decodeJSON(req.Target, &target); err != nil {
		return nil, false, newAPIError(400, "invalid_target", "target.path is required")
	}
	resolved, apiErr := s.resolveAllowedPath(target.Path)
	if apiErr != nil {
		return nil, false, apiErr
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, newAPIError(404, "not_found", "target path does not exist")
		}
		return nil, false, newAPIError(500, "stat_failed", "could not stat target path")
	}

	data := map[string]any{
		"path":     resolved,
		"mode":     info.Mode().String(),
		"size":     info.Size(),
		"mod_time": info.ModTime().UTC().Format(time.RFC3339Nano),
		"type":     fileType(info.Mode()),
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		if link, err := os.Readlink(resolved); err == nil {
			data["symlink_target"] = link
		}
	}
	return data, false, nil
}

func (s *Service) filesystemRead(req RequestEnvelope) (any, bool, *APIError) {
	target, params, apiErr := s.decodePathAndRead(req)
	if apiErr != nil {
		return nil, false, apiErr
	}
	resolved, apiErr := s.resolveAllowedPath(target.Path)
	if apiErr != nil {
		return nil, false, apiErr
	}

	if params.Offset < 0 {
		return nil, false, newAPIError(400, "invalid_params", "offset must be non-negative")
	}
	maxBytes := params.MaxBytes
	if maxBytes <= 0 || maxBytes > s.cfg.MaxReadBytes {
		maxBytes = s.cfg.MaxReadBytes
	}

	file, err := os.Open(resolved)
	if err != nil {
		if os.IsPermission(err) {
			return nil, false, newAPIError(403, "permission_denied", "could not read file")
		}
		return nil, false, newAPIError(500, "read_failed", "could not open file")
	}
	defer file.Close()

	if _, err := file.Seek(params.Offset, io.SeekStart); err != nil {
		return nil, false, newAPIError(400, "invalid_params", "offset could not be applied")
	}

	limitReader := io.LimitReader(file, maxBytes+1)
	content, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, false, newAPIError(500, "read_failed", "could not read file")
	}

	truncated := int64(len(content)) > maxBytes
	if truncated {
		content = content[:maxBytes]
	}

	return map[string]any{
		"path":       resolved,
		"offset":     params.Offset,
		"bytes_read": len(content),
		"content":    encodeContent(content),
	}, truncated, nil
}

func (s *Service) filesystemTail(req RequestEnvelope) (any, bool, *APIError) {
	target, params, apiErr := s.decodePathAndRead(req)
	if apiErr != nil {
		return nil, false, apiErr
	}
	resolved, apiErr := s.resolveAllowedPath(target.Path)
	if apiErr != nil {
		return nil, false, apiErr
	}

	maxBytes := params.MaxBytes
	if maxBytes <= 0 || maxBytes > s.cfg.MaxTailBytes {
		maxBytes = s.cfg.MaxTailBytes
	}

	file, err := os.Open(resolved)
	if err != nil {
		if os.IsPermission(err) {
			return nil, false, newAPIError(403, "permission_denied", "could not read file")
		}
		return nil, false, newAPIError(500, "tail_failed", "could not open file")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, false, newAPIError(500, "tail_failed", "could not stat file")
	}
	size := info.Size()
	offset := size - maxBytes
	if offset < 0 {
		offset = 0
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, false, newAPIError(500, "tail_failed", "could not seek file")
	}

	content, err := io.ReadAll(io.LimitReader(file, maxBytes))
	if err != nil {
		return nil, false, newAPIError(500, "tail_failed", "could not read file")
	}

	lines := []string{}
	if utf8.Valid(content) {
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
	}

	return map[string]any{
		"path":       resolved,
		"start":      offset,
		"bytes_read": len(content),
		"content":    encodeContent(content),
		"lines":      lines,
	}, offset > 0, nil
}

func (s *Service) processList() (any, bool, *APIError) {
	entries, err := os.ReadDir(s.cfg.ProcRoot)
	if err != nil {
		return nil, false, newAPIError(500, "process_list_failed", "could not read proc root")
	}

	records := make([]processRecord, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		record := processRecord{PID: pid}
		statusPath := filepath.Join(s.cfg.ProcRoot, entry.Name(), "status")
		if content, err := os.ReadFile(statusPath); err == nil {
			parseProcStatus(content, &record)
		}
		cmdlinePath := filepath.Join(s.cfg.ProcRoot, entry.Name(), "cmdline")
		if content, err := os.ReadFile(cmdlinePath); err == nil {
			record.Cmdline = strings.ReplaceAll(strings.TrimRight(string(content), "\x00"), "\x00", " ")
		}
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool { return records[i].PID < records[j].PID })
	truncated := len(records) > s.cfg.MaxProcessEntries
	if truncated {
		records = records[:s.cfg.MaxProcessEntries]
	}

	return map[string]any{
		"processes": records,
		"count":     len(records),
	}, truncated, nil
}

func (s *Service) decodePathAndList(req RequestEnvelope) (pathTarget, listParams, *APIError) {
	var target pathTarget
	var params listParams
	if err := decodeJSON(req.Target, &target); err != nil {
		return target, params, newAPIError(400, "invalid_target", "target.path is required")
	}
	if len(req.Params) > 0 {
		if err := decodeJSON(req.Params, &params); err != nil {
			return target, params, newAPIError(400, "invalid_params", "params are malformed")
		}
	}
	return target, params, nil
}

func (s *Service) decodePathAndRead(req RequestEnvelope) (pathTarget, readParams, *APIError) {
	var target pathTarget
	var params readParams
	if err := decodeJSON(req.Target, &target); err != nil {
		return target, params, newAPIError(400, "invalid_target", "target.path is required")
	}
	if len(req.Params) > 0 {
		if err := decodeJSON(req.Params, &params); err != nil {
			return target, params, newAPIError(400, "invalid_params", "params are malformed")
		}
	}
	return target, params, nil
}

func decodeJSON(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		return fmt.Errorf("missing payload")
	}
	return json.Unmarshal(raw, target)
}

func fileType(mode fs.FileMode) string {
	switch {
	case mode.IsDir():
		return "directory"
	case mode&fs.ModeSymlink != 0:
		return "symlink"
	default:
		return "file"
	}
}

func readTrimmedFile(path string) (string, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(content)), true
}

func readProcUptime(procRoot string) (float64, bool) {
	content, ok := readTrimmedFile(filepath.Join(procRoot, "uptime"))
	if !ok {
		return 0, false
	}
	parts := strings.Fields(content)
	if len(parts) == 0 {
		return 0, false
	}
	uptime, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0, false
	}
	return uptime, true
}

func parseProcStatus(content []byte, record *processRecord) {
	for _, line := range strings.Split(string(content), "\n") {
		switch {
		case strings.HasPrefix(line, "Name:"):
			record.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "State:"):
			record.State = strings.TrimSpace(strings.TrimPrefix(line, "State:"))
		case strings.HasPrefix(line, "PPid:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			if parsed, err := strconv.Atoi(value); err == nil {
				record.PPID = parsed
			}
		}
	}
}

func encodeContent(content []byte) map[string]any {
	if utf8.Valid(content) {
		return map[string]any{
			"format": "text/plain; charset=utf-8",
			"raw":    string(content),
		}
	}
	return map[string]any{
		"format": "application/octet-stream;base64",
		"raw":    base64.StdEncoding.EncodeToString(content),
	}
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func canonicalizeRoots(roots []string) []string {
	canonical := make([]string, 0, len(roots))
	for _, root := range roots {
		resolved, err := filepath.EvalSymlinks(root)
		if err == nil {
			canonical = append(canonical, filepath.Clean(resolved))
			continue
		}
		canonical = append(canonical, filepath.Clean(root))
	}
	return canonical
}
