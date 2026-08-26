package agent

import (
	"os"
	"path/filepath"
	"strings"
)

func (s *Service) resolveAllowedPath(path string) (string, *APIError) {
	if path == "" {
		return "", newAPIError(400, "invalid_target", "target.path is required")
	}
	if !filepath.IsAbs(path) {
		return "", newAPIError(400, "invalid_target", "target.path must be absolute")
	}

	cleaned := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return "", newAPIError(404, "not_found", "target path does not exist")
		}
		return "", newAPIError(400, "invalid_target", "target path could not be resolved")
	}
	resolved = filepath.Clean(resolved)

	for _, root := range s.cfg.AllowedRoots {
		if resolved == root || strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
			return resolved, nil
		}
	}
	return "", newAPIError(403, "path_not_allowed", "target path is outside allowed roots")
}
