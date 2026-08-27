package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/maclach/sroiaaa/internal/broker"
)

const (
	zabbixDefaultTimeout   = 15 * time.Second
	zabbixMaxResponseBytes = 1 << 20
	zabbixMaxLimit         = 500
)

// zabbixMethods is the fixed action table. A plan may only name an action that
// appears here, so neither a client nor a model can select an arbitrary Zabbix
// API method.
var zabbixMethods = map[string]string{
	"trigger.get": "trigger.get",
}

// ZabbixConfig carries operator-supplied execution details. None of these are
// derived from a route plan.
type ZabbixConfig struct {
	Endpoint         string
	Token            string
	Timeout          time.Duration
	MaxResponseBytes int64
}

// ZabbixConnector executes zabbix-api route steps.
type ZabbixConnector struct {
	endpoint         string
	token            string
	maxResponseBytes int64
	client           *http.Client
}

// NewZabbixConnector validates configuration and returns a connector.
func NewZabbixConnector(config ZabbixConfig) (*ZabbixConnector, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("zabbix endpoint is required")
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse zabbix endpoint: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("zabbix endpoint must be http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("zabbix endpoint must include a host")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("zabbix token is required")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = zabbixDefaultTimeout
	}
	maxBytes := config.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = zabbixMaxResponseBytes
	}

	return &ZabbixConnector{
		endpoint:         config.Endpoint,
		token:            config.Token,
		maxResponseBytes: maxBytes,
		client:           &http.Client{Timeout: timeout},
	}, nil
}

// Source reports which route-step source this connector serves.
func (c *ZabbixConnector) Source() broker.Source {
	return broker.SourceZabbixAPI
}

// Execute runs one route step and returns normalized evidence.
func (c *ZabbixConnector) Execute(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Source != broker.SourceZabbixAPI {
		return Evidence{}, newConnectorError("wrong_source", "step is not a zabbix-api step")
	}
	method, ok := zabbixMethods[step.Action]
	if !ok {
		return Evidence{}, newConnectorError("unsupported_action", fmt.Sprintf("action %q is not executable", step.Action))
	}

	limit := step.Limit
	if limit <= 0 || limit > zabbixMaxLimit {
		limit = zabbixMaxLimit
	}

	params := map[string]any{
		"output":      []string{"triggerid", "description", "priority", "value", "lastchange"},
		"selectHosts": []string{"host"},
		// Without this, trigger descriptions come back with unresolved macros
		// such as {HOST.NAME}, which a model will faithfully recite at a reader.
		"expandDescription": true,
		"only_true":         true,
		"monitored":         true,
		"skipDependent":     true,
		"sortfield":         "priority",
		"sortorder":         "DESC",
		"limit":             limit,
	}
	if step.Host != "" {
		params["host"] = step.Host
	}

	requestedAt := time.Now().UTC()
	result, _, err := c.call(ctx, method, params)
	if err != nil {
		return Evidence{}, err
	}

	// Zabbix does not report how many rows matched, so a limited result is
	// indistinguishable from a complete one. Ask separately for the true count,
	// otherwise a model will state the plan's limit as though it were the
	// population.
	total, err := c.count(ctx, method, params)
	if err != nil {
		return Evidence{}, err
	}

	items := normalizeTriggers(result)
	return Evidence{
		Source:         string(broker.SourceZabbixAPI),
		Action:         step.Action,
		Endpoint:       redactEndpoint(c.endpoint),
		RequestedAt:    requestedAt,
		DurationMS:     time.Since(requestedAt).Milliseconds(),
		ItemCount:      len(items),
		TotalAvailable: total,
		Truncated:      total > len(items),
		Summary:        summarizeTriggers(items, total),
		Items:          items,
	}, nil
}

// count asks how many rows match the same filters, so the caller can tell a
// bounded page from a complete answer.
func (c *ZabbixConnector) count(ctx context.Context, method string, params map[string]any) (int, error) {
	countParams := make(map[string]any, len(params))
	for key, value := range params {
		switch key {
		case "limit", "sortfield", "sortorder", "output", "selectHosts", "expandDescription":
			continue
		}
		countParams[key] = value
	}
	countParams["countOutput"] = true

	payload, err := c.rawCall(ctx, method, countParams)
	if err != nil {
		return 0, err
	}

	// countOutput returns the total as a JSON string.
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return 0, newConnectorError("decode_response", err.Error())
	}
	var asString string
	if err := json.Unmarshal(envelope.Result, &asString); err == nil {
		parsed, err := strconv.Atoi(asString)
		if err != nil {
			return 0, newConnectorError("decode_response", "unparseable count: "+asString)
		}
		return parsed, nil
	}
	var asNumber int
	if err := json.Unmarshal(envelope.Result, &asNumber); err != nil {
		return 0, newConnectorError("decode_response", "unexpected count shape")
	}
	return asNumber, nil
}

// zabbixTrigger mirrors only the fields we consume. Additional fields in a
// response are ignored rather than rejected, because the remote API may add
// fields without our involvement.
type zabbixTrigger struct {
	TriggerID   string `json:"triggerid"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Value       string `json:"value"`
	LastChange  string `json:"lastchange"`
	Hosts       []struct {
		Host string `json:"host"`
	} `json:"hosts"`
}

type zabbixEnvelope struct {
	Result []zabbixTrigger `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	} `json:"error"`
}

// rawCall performs the bounded HTTP round trip and returns the response body.
func (c *ZabbixConnector) rawCall(ctx context.Context, method string, params map[string]any) ([]byte, error) {
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
	if err != nil {
		return nil, newConnectorError("encode_request", err.Error())
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, newConnectorError("build_request", err.Error())
	}
	request.Header.Set("Content-Type", "application/json-rpc")
	request.Header.Set("Authorization", "Bearer "+c.token)

	response, err := c.client.Do(request)
	if err != nil {
		return nil, newConnectorError("transport", err.Error())
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, newConnectorError("http_status", "zabbix returned HTTP "+strconv.Itoa(response.StatusCode))
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, newConnectorError("read_response", err.Error())
	}
	if int64(len(body)) > c.maxResponseBytes {
		return nil, newConnectorError("response_too_large", fmt.Sprintf("response exceeded %d bytes", c.maxResponseBytes))
	}
	return body, nil
}

func (c *ZabbixConnector) call(ctx context.Context, method string, params map[string]any) ([]zabbixTrigger, bool, error) {
	body, err := c.rawCall(ctx, method, params)
	if err != nil {
		return nil, false, err
	}

	var envelope zabbixEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false, newConnectorError("decode_response", err.Error())
	}
	if envelope.Error != nil {
		return nil, false, newConnectorError("zabbix_error", envelope.Error.Message+": "+envelope.Error.Data)
	}
	return envelope.Result, false, nil
}

// zabbixPriority maps Zabbix numeric trigger priorities to readable severities.
var zabbixPriority = map[string]string{
	"0": "not classified",
	"1": "information",
	"2": "warning",
	"3": "average",
	"4": "high",
	"5": "disaster",
}

func normalizeTriggers(triggers []zabbixTrigger) []EvidenceItem {
	items := make([]EvidenceItem, 0, len(triggers))
	for _, trigger := range triggers {
		host := ""
		if len(trigger.Hosts) > 0 {
			host = trigger.Hosts[0].Host
		}
		severity, ok := zabbixPriority[trigger.Priority]
		if !ok {
			severity = "unknown"
		}
		state := "ok"
		if trigger.Value == "1" {
			state = "problem"
		}

		item := EvidenceItem{
			ID:          trigger.TriggerID,
			Host:        host,
			Description: trigger.Description,
			Severity:    severity,
			State:       state,
		}
		if trigger.LastChange != "" {
			// Zabbix reports epoch seconds. Passing that through unchanged
			// invites a model to repeat the raw integer at a reader, so it is
			// rendered here instead.
			item.Fields = map[string]string{"last_change": formatEpoch(trigger.LastChange)}
		}
		items = append(items, item)
	}
	return items
}

// redactEndpoint records the host a request went to without carrying any
// credential material that may sit in the URL.
func redactEndpoint(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "invalid-endpoint"
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.Path
}

// summarizeTriggers counts problems by severity so a model never has to tally
// them itself.
func summarizeTriggers(items []EvidenceItem, totalMatching int) map[string]int {
	// "returned" and "total_matching" are kept distinct so a model cannot
	// mistake a bounded page for the whole population.
	summary := map[string]int{
		"returned":       len(items),
		"total_matching": totalMatching,
	}
	for _, item := range items {
		if item.Severity != "" {
			summary[item.Severity]++
		}
	}
	return summary
}

// formatEpoch renders Zabbix epoch seconds as RFC 3339, leaving anything
// unparseable untouched rather than guessing.
func formatEpoch(value string) string {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return value
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}
