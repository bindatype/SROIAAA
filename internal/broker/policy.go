package broker

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	policyVersion      = 1
	maxResourceNameLen = 64
	maxHostSelectorLen = 253
	maxPolicyReadBytes = 65536
	maxPolicyListItems = 256
)

func LoadPolicy(r io.Reader) (Policy, error) {
	var policy Policy
	if err := decodeOneJSON(r, &policy); err != nil {
		return Policy{}, fmt.Errorf("decode broker policy: %w", err)
	}
	return policy, nil
}

func DecodeRouteRequest(r io.Reader) (RouteRequest, error) {
	var request RouteRequest
	if err := decodeOneJSON(r, &request); err != nil {
		return RouteRequest{}, fmt.Errorf("decode route request: %w", err)
	}
	return request, nil
}

func decodeOneJSON(r io.Reader, destination any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validatePolicy(policy Policy) error {
	if policy.Version != policyVersion {
		return fmt.Errorf("policy version must be %d", policyVersion)
	}
	if policy.LiveHosts == nil {
		return fmt.Errorf("live_hosts must be present")
	}
	if policy.Resources == nil {
		return fmt.Errorf("resources must be present")
	}

	for name, resource := range policy.Resources {
		if err := validateResourceName(name); err != nil {
			return fmt.Errorf("resource %q: %w", name, err)
		}
		if err := validateResource(resource); err != nil {
			return fmt.Errorf("resource %q: %w", name, err)
		}
	}

	for host, hostPolicy := range policy.LiveHosts {
		if err := validateHostSelector(host); err != nil {
			return fmt.Errorf("live host %q: %w", host, err)
		}
		seen := make(map[string]struct{}, len(hostPolicy.Resources))
		for _, resourceName := range hostPolicy.Resources {
			if _, ok := policy.Resources[resourceName]; !ok {
				return fmt.Errorf("live host %q references unknown resource %q", host, resourceName)
			}
			if _, ok := seen[resourceName]; ok {
				return fmt.Errorf("live host %q repeats resource %q", host, resourceName)
			}
			seen[resourceName] = struct{}{}
		}
	}
	return nil
}

func validateResourceName(name string) error {
	if name == "" || len(name) > maxResourceNameLen {
		return fmt.Errorf("name must contain 1-%d characters", maxResourceNameLen)
	}
	for _, char := range name {
		if unicode.IsLower(char) || unicode.IsDigit(char) || char == '.' || char == '-' || char == '_' {
			continue
		}
		return fmt.Errorf("name may contain only lowercase letters, digits, dot, dash, and underscore")
	}
	return nil
}

func validateHostSelector(host string) error {
	if host == "" || len(host) > maxHostSelectorLen || strings.TrimSpace(host) != host {
		return fmt.Errorf("host must contain 1-%d non-whitespace characters", maxHostSelectorLen)
	}
	for _, char := range host {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || char == '.' || char == '-' || char == '_' {
			continue
		}
		return fmt.Errorf("host contains an unsupported character")
	}
	return nil
}

func validateResource(resource Resource) error {
	if !filepath.IsAbs(resource.Path) {
		return fmt.Errorf("path must be absolute")
	}
	if filepath.Clean(resource.Path) != resource.Path {
		return fmt.Errorf("path must be canonical")
	}

	params := OperationParams{}
	if resource.Params != nil {
		params = *resource.Params
	}
	if params.Offset < 0 || params.MaxBytes < 0 || params.MaxEntries < 0 {
		return fmt.Errorf("operation limits must not be negative")
	}

	switch resource.Operation {
	case "filesystem.list":
		if params.MaxEntries < 1 || params.MaxEntries > maxPolicyListItems {
			return fmt.Errorf("filesystem.list requires max_entries between 1 and %d", maxPolicyListItems)
		}
		if params.Offset != 0 || params.MaxBytes != 0 {
			return fmt.Errorf("filesystem.list accepts only max_entries")
		}
	case "filesystem.stat":
		if params != (OperationParams{}) {
			return fmt.Errorf("filesystem.stat does not accept parameters")
		}
	case "filesystem.read":
		if params.MaxBytes < 1 || params.MaxBytes > maxPolicyReadBytes {
			return fmt.Errorf("filesystem.read requires max_bytes between 1 and %d", maxPolicyReadBytes)
		}
		if params.MaxEntries != 0 {
			return fmt.Errorf("filesystem.read does not accept max_entries")
		}
	case "filesystem.tail":
		if params.MaxBytes < 1 || params.MaxBytes > maxPolicyReadBytes {
			return fmt.Errorf("filesystem.tail requires max_bytes between 1 and %d", maxPolicyReadBytes)
		}
		if params.Offset != 0 || params.MaxEntries != 0 {
			return fmt.Errorf("filesystem.tail accepts only max_bytes")
		}
	default:
		return fmt.Errorf("operation %q is not broker-routable", resource.Operation)
	}
	return nil
}
