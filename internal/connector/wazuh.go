package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maclach/sroiaaa/internal/broker"
)

const (
	wazuhDefaultTimeout   = 20 * time.Second
	wazuhMaxResponseBytes = 1 << 21
	wazuhMaxLimit         = 500
	wazuhTokenTTL         = 10 * time.Minute
	wazuhAgentFields      = "id,name,ip,status,version,lastKeepAlive"
	// managerAgentID is the Wazuh manager's own entry. GET /agents includes it;
	// the manager's own summary endpoint does not. Excluding it from aggregate
	// counts keeps our numbers equal to what the Wazuh dashboard reports.
	managerAgentID = "000"
)

// wazuhActions is the fixed action table. Route plans may only name an action
// listed here, so no client or model can reach an arbitrary API path.
var wazuhActions = map[string]struct{}{
	"agents.list":   {},
	"agents.status": {},
}

// WazuhConfig carries operator-supplied execution details. None are derived
// from a route plan.
type WazuhConfig struct {
	Endpoint         string
	Username         string
	Password         string
	Timeout          time.Duration
	MaxResponseBytes int64
	// InsecureSkipVerify disables TLS verification. The RTS deployment presents
	// a self-signed certificate, so this is required in practice there, but it
	// is never the default: an operator must opt in deliberately.
	InsecureSkipVerify bool
}

// WazuhConnector executes wazuh-api route steps against the manager plane.
//
// This connector deliberately speaks only to the Wazuh API on 55000, never to
// the Indexer on 9200. Inventory and status are manager-plane questions; alert
// search belongs to the Indexer and is out of scope here.
type WazuhConnector struct {
	endpoint         string
	username         string
	password         string
	maxResponseBytes int64
	client           *http.Client

	mu        sync.Mutex
	token     string
	tokenTime time.Time
}

// NewWazuhConnector validates configuration and returns a connector.
func NewWazuhConnector(config WazuhConfig) (*WazuhConnector, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("wazuh endpoint is required")
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse wazuh endpoint: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("wazuh endpoint must be http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("wazuh endpoint must include a host")
	}
	if config.Username == "" || config.Password == "" {
		return nil, fmt.Errorf("wazuh username and password are required")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = wazuhDefaultTimeout
	}
	maxBytes := config.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = wazuhMaxResponseBytes
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if config.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &WazuhConnector{
		endpoint:         strings.TrimRight(config.Endpoint, "/"),
		username:         config.Username,
		password:         config.Password,
		maxResponseBytes: maxBytes,
		client:           &http.Client{Timeout: timeout, Transport: transport},
	}, nil
}

// Source reports which route-step source this connector serves.
func (c *WazuhConnector) Source() broker.Source {
	return broker.SourceWazuhAPI
}

// Execute runs one route step and returns normalized evidence.
func (c *WazuhConnector) Execute(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Source != broker.SourceWazuhAPI {
		return Evidence{}, newConnectorError("wrong_source", "step is not a wazuh-api step")
	}
	if _, ok := wazuhActions[step.Action]; !ok {
		return Evidence{}, newConnectorError("unsupported_action", fmt.Sprintf("action %q is not executable", step.Action))
	}

	query := url.Values{}
	query.Set("select", wazuhAgentFields)

	switch step.Action {
	case "agents.list":
		limit := step.Limit
		if limit <= 0 || limit > wazuhMaxLimit {
			limit = wazuhMaxLimit
		}
		query.Set("limit", strconv.Itoa(limit))
	case "agents.status":
		if step.Host == "" {
			return Evidence{}, newConnectorError("missing_host", "agents.status requires a host")
		}
		query.Set("name", step.Host)
	}

	requestedAt := time.Now().UTC()
	payload, err := c.get(ctx, "/agents", query)
	if err != nil {
		return Evidence{}, err
	}

	items := normalizeAgents(payload.Data.AffectedItems)
	return Evidence{
		Source:         string(broker.SourceWazuhAPI),
		Action:         step.Action,
		Endpoint:       redactEndpoint(c.endpoint),
		RequestedAt:    requestedAt,
		DurationMS:     time.Since(requestedAt).Milliseconds(),
		ItemCount:      len(items),
		TotalAvailable: payload.Data.TotalAffectedItems,
		Truncated:      payload.Data.TotalAffectedItems > len(items),
		Summary:        summarizeAgents(payload.Data.AffectedItems),
		Items:          items,
	}, nil
}

// wazuhAgent mirrors only the fields we consume.
type wazuhAgent struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	LastKeepAlive string `json:"lastKeepAlive"`
}

type wazuhEnvelope struct {
	Data struct {
		AffectedItems      []wazuhAgent `json:"affected_items"`
		TotalAffectedItems int          `json:"total_affected_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

// authenticate obtains a JWT from the manager and caches it briefly. Wazuh
// tokens are short-lived, so the cache is bounded well inside their lifetime
// rather than tracking expiry claims.
func (c *WazuhConnector) authenticate(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Since(c.tokenTime) < wazuhTokenTTL {
		return c.token, nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/security/user/authenticate?raw=true", nil)
	if err != nil {
		return "", newConnectorError("build_request", err.Error())
	}
	request.SetBasicAuth(c.username, c.password)

	response, err := c.client.Do(request)
	if err != nil {
		return "", newConnectorError("transport", err.Error())
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", newConnectorError("authentication_failed", "wazuh authenticate returned HTTP "+strconv.Itoa(response.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8192))
	if err != nil {
		return "", newConnectorError("read_response", err.Error())
	}
	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", newConnectorError("authentication_failed", "wazuh returned an empty token")
	}

	c.token = token
	c.tokenTime = time.Now()
	return token, nil
}

func (c *WazuhConnector) get(ctx context.Context, path string, query url.Values) (wazuhEnvelope, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return wazuhEnvelope{}, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path+"?"+query.Encode(), nil)
	if err != nil {
		return wazuhEnvelope{}, newConnectorError("build_request", err.Error())
	}
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := c.client.Do(request)
	if err != nil {
		return wazuhEnvelope{}, newConnectorError("transport", err.Error())
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return wazuhEnvelope{}, newConnectorError("http_status", "wazuh returned HTTP "+strconv.Itoa(response.StatusCode))
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return wazuhEnvelope{}, newConnectorError("read_response", err.Error())
	}
	if int64(len(body)) > c.maxResponseBytes {
		return wazuhEnvelope{}, newConnectorError("response_too_large", fmt.Sprintf("response exceeded %d bytes", c.maxResponseBytes))
	}

	var envelope wazuhEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return wazuhEnvelope{}, newConnectorError("decode_response", err.Error())
	}
	if envelope.Error != 0 {
		return wazuhEnvelope{}, newConnectorError("wazuh_error", fmt.Sprintf("wazuh error %d: %s", envelope.Error, envelope.Message))
	}
	return envelope, nil
}

func normalizeAgents(agents []wazuhAgent) []EvidenceItem {
	items := make([]EvidenceItem, 0, len(agents))
	for _, agent := range agents {
		item := EvidenceItem{
			ID:          agent.ID,
			Host:        agent.Name,
			Description: strings.TrimSpace("Wazuh agent " + agent.Version),
			State:       agent.Status,
		}
		fields := map[string]string{}
		if agent.IP != "" {
			fields["ip"] = agent.IP
		}
		if agent.LastKeepAlive != "" {
			fields["last_keep_alive"] = agent.LastKeepAlive
		}
		if len(fields) > 0 {
			item.Fields = fields
		}
		items = append(items, item)
	}
	return items
}

// summarizeAgents counts agents by connection state. The Wazuh manager's own
// record is excluded so these totals match the manager's summary endpoint and
// the Wazuh dashboard.
func summarizeAgents(agents []wazuhAgent) map[string]int {
	summary := map[string]int{"total": 0}
	for _, agent := range agents {
		if agent.ID == managerAgentID {
			continue
		}
		state := agent.Status
		if state == "" {
			state = "unknown"
		}
		summary[state]++
		summary["total"]++
	}
	return summary
}
