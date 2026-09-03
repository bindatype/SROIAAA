package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maclach/sroiaaa/internal/broker"
)

const (
	sroiaaaDefaultTimeout   = 20 * time.Second
	sroiaaaMaxResponseBytes = 128 << 10
)

// SROIAAAAgentConfig is one endpoint agent an operator has explicitly made
// reachable. Host is the broker-policy name, not a DNS name selected by a
// route plan.
type SROIAAAAgentConfig struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
}

// SROIAAAConfig maps every permitted policy host to its endpoint and its own
// bearer token. Keeping the map in operator configuration prevents a route
// plan from selecting either a network destination or another host's token.
type SROIAAAConfig struct {
	Agents           map[string]SROIAAAAgentConfig
	Timeout          time.Duration
	MaxResponseBytes int64
}

// ParseSROIAAAAgents reads the value of SROIAAA_AGENT_CONFIG. It intentionally
// keeps endpoint and token together per host: a single shared token would make
// one endpoint credential authority for every configured agent.
func ParseSROIAAAAgents(value string) (map[string]SROIAAAAgentConfig, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("agent configuration is empty")
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var agents map[string]SROIAAAAgentConfig
	if err := decoder.Decode(&agents); err != nil {
		return nil, fmt.Errorf("decode agent configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("agent configuration contains multiple JSON values")
		}
		return nil, fmt.Errorf("decode agent configuration: %w", err)
	}
	if len(agents) == 0 {
		return nil, fmt.Errorf("agent configuration contains no hosts")
	}
	return agents, nil
}

type configuredAgent struct {
	endpoint string
	token    string
}

// SROIAAAConnector executes broker-approved operations against the endpoint
// agent. The broker has already fixed operation, path, and limits; this
// connector's job is only to bind that step to the configured host endpoint.
type SROIAAAConnector struct {
	agents           map[string]configuredAgent
	maxResponseBytes int64
	client           *http.Client
}

// NewSROIAAAConnector validates operator configuration before accepting any
// plan. HTTP is allowed only for loopback development agents; a remotely
// reachable endpoint must use HTTPS.
func NewSROIAAAConnector(config SROIAAAConfig) (*SROIAAAConnector, error) {
	if len(config.Agents) == 0 {
		return nil, fmt.Errorf("at least one endpoint agent is required")
	}

	agents := make(map[string]configuredAgent, len(config.Agents))
	for host, agent := range config.Agents {
		if strings.TrimSpace(host) == "" || strings.TrimSpace(host) != host {
			return nil, fmt.Errorf("endpoint agent host must be non-empty and have no surrounding whitespace")
		}
		if strings.TrimSpace(agent.Token) == "" {
			return nil, fmt.Errorf("endpoint agent %q token is required", host)
		}
		endpoint, err := validateSROIAAAEndpoint(host, agent.Endpoint)
		if err != nil {
			return nil, err
		}
		agents[host] = configuredAgent{endpoint: endpoint, token: agent.Token}
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = sroiaaaDefaultTimeout
	}
	maxBytes := config.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = sroiaaaMaxResponseBytes
	}

	return &SROIAAAConnector{
		agents:           agents,
		maxResponseBytes: maxBytes,
		// An agent controls its HTTP response, not the broker's destination.
		// Following a redirect would send its bearer token to an arbitrary URL.
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func validateSROIAAAEndpoint(host, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("endpoint agent %q endpoint is required", host)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse endpoint agent %q endpoint: %w", host, err)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("endpoint agent %q endpoint must be a bare HTTP(S) origin", host)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("endpoint agent %q endpoint must not contain a path", host)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return "", fmt.Errorf("endpoint agent %q endpoint must use https (http is permitted only for loopback development)", host)
	}
	return strings.TrimRight(value, "/"), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

// Source reports which route-step source this connector serves.
func (c *SROIAAAConnector) Source() broker.Source {
	return broker.SourceSROIAAA
}

type agentOperationRequest struct {
	Operation string                  `json:"operation"`
	Target    *broker.OperationTarget `json:"target,omitempty"`
	Params    *broker.OperationParams `json:"params,omitempty"`
}

type agentOperationResponse struct {
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
	Metadata  struct {
		Truncated bool `json:"truncated"`
	} `json:"metadata"`
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Execute sends only the policy-derived operation, target, and limits to the
// endpoint. A plan for one configured host cannot be sent to another.
func (c *SROIAAAConnector) Execute(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Source != broker.SourceSROIAAA {
		return Evidence{}, newConnectorError("wrong_source", "step is not a sroiaaa-agent step")
	}
	if step.Action != "operations.execute" || step.Operation == "" || step.Target == nil {
		return Evidence{}, newConnectorError("invalid_step", "sroiaaa-agent step must contain a policy-approved operation and target")
	}
	agent, ok := c.agents[step.Host]
	if !ok {
		return Evidence{}, newConnectorError("host_not_configured", "no endpoint agent is configured for the policy host")
	}

	payload, err := json.Marshal(agentOperationRequest{
		Operation: step.Operation,
		Target:    step.Target,
		Params:    step.Params,
	})
	if err != nil {
		return Evidence{}, fmt.Errorf("encode endpoint agent request: %w", err)
	}

	requestedAt := time.Now().UTC()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, agent.endpoint+"/v1/operations", bytes.NewReader(payload))
	if err != nil {
		return Evidence{}, fmt.Errorf("build endpoint agent request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+agent.token)

	response, err := c.client.Do(request)
	if err != nil {
		return Evidence{}, newConnectorError("transport_failed", err.Error())
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return Evidence{}, newConnectorError("read_response", err.Error())
	}
	if int64(len(raw)) > c.maxResponseBytes {
		return Evidence{}, newConnectorError("response_too_large", fmt.Sprintf("endpoint agent response exceeded %d bytes", c.maxResponseBytes))
	}

	var decoded agentOperationResponse
	if response.StatusCode != http.StatusOK {
		// A proxy or an agent may send an HTML error page. Its body is not
		// evidence and need not be valid agent JSON to report the failure.
		_ = json.Unmarshal(raw, &decoded)
		return Evidence{}, agentResponseError(response.StatusCode, decoded)
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Evidence{}, newConnectorError("decode_response", err.Error())
	}
	if decoded.Status != "ok" {
		return Evidence{}, agentResponseError(response.StatusCode, decoded)
	}
	if decoded.Operation != step.Operation {
		return Evidence{}, newConnectorError("response_mismatch", "endpoint agent response operation did not match the approved operation")
	}
	if len(decoded.Data) == 0 {
		return Evidence{}, newConnectorError("decode_response", "endpoint agent response omitted data")
	}
	var data any
	if err := json.Unmarshal(decoded.Data, &data); err != nil {
		return Evidence{}, newConnectorError("decode_response", fmt.Sprintf("endpoint agent data: %v", err))
	}

	return Evidence{
		Source:      string(broker.SourceSROIAAA),
		Action:      step.Action,
		Endpoint:    redactEndpoint(agent.endpoint),
		RequestedAt: requestedAt,
		DurationMS:  time.Since(requestedAt).Milliseconds(),
		Truncated:   decoded.Metadata.Truncated,
		Data:        data,
	}, nil
}

func agentResponseError(status int, response agentOperationResponse) error {
	code := "agent_error"
	switch status {
	case http.StatusUnauthorized:
		code = "authentication_failed"
	case http.StatusForbidden:
		code = "authorization_failed"
	case http.StatusNotFound:
		code = "not_found"
	}
	if response.Error != nil {
		if response.Error.Code != "" {
			code = response.Error.Code
		}
		if response.Error.Message != "" {
			return newConnectorError(code, response.Error.Message)
		}
	}
	return newConnectorError(code, fmt.Sprintf("endpoint agent returned HTTP %d", status))
}
