package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/maclach/sroiaaa/internal/broker"
	"github.com/maclach/sroiaaa/internal/connector"
)

const (
	zabbixEndpointEnv  = "SROIAAA_ZABBIX_ENDPOINT"
	zabbixTokenEnv     = "ZABBIX_RO_TOKEN"
	wazuhEndpointEnv   = "SROIAAA_WAZUH_ENDPOINT"
	wazuhUsernameEnv   = "WAZUH_API_USERNAME"
	wazuhPasswordEnv   = "WAZUH_API_PASSWORD"
	pegasusDSNEnv      = "SROIAAA_PEGASUS_DSN"
	pegasusMaxRowsEnv  = "SROIAAA_PEGASUS_MAX_ROWS"
	pegasusMaxBytesEnv = "SROIAAA_PEGASUS_MAX_BYTES"
	rtEndpointEnv      = "SROIAAA_RT_ENDPOINT"
	rtTokenEnv         = "RT_API_TOKEN"
	// rtQueuesEnv names the RT queues this deployment allows searching, as a
	// comma-separated list. Site configuration, so it lives here rather than
	// in the connector: RT queues are organization-specific and there is no
	// safe default that includes any of them.
	rtQueuesEnv = "SROIAAA_RT_QUEUES"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sroiaaa-broker-exec", flag.ContinueOnError)
	flags.SetOutput(stderr)
	policyPath := flags.String("policy", "", "broker policy the plan is verified against (required)")
	zabbixEndpoint := flags.String("zabbix-endpoint", os.Getenv(zabbixEndpointEnv), "Zabbix JSON-RPC endpoint URL")
	wazuhEndpoint := flags.String("wazuh-endpoint", os.Getenv(wazuhEndpointEnv), "Wazuh API base URL")
	wazuhInsecure := flags.Bool("wazuh-insecure", false, "skip TLS verification for the Wazuh API (required where the manager presents a self-signed certificate)")
	rtEndpoint := flags.String("rt-endpoint", os.Getenv(rtEndpointEnv), "Request Tracker REST 2.0 base URL")
	timeout := flags.Duration("timeout", 20*time.Second, "overall execution timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if *policyPath == "" {
		fmt.Fprintln(stderr, "sroiaaa-broker-exec: -policy is required")
		return 2
	}

	plan, err := decodePlan(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "sroiaaa-broker-exec: %v\n", err)
		return 1
	}

	// A plan is an ordinary JSON document and arrives here from an untrusted
	// caller. Authorization happened when the planner ran; it is re-established
	// here rather than assumed, so that a hand-written plan cannot execute.
	if err := verifyPlan(*policyPath, plan); err != nil {
		fmt.Fprintf(stderr, "sroiaaa-broker-exec: %v\n", err)
		return 1
	}

	if *wazuhInsecure {
		fmt.Fprintln(stderr, "sroiaaa-broker-exec: warning: Wazuh TLS verification is disabled")
	}
	connectors, err := buildConnectors(plan, connectorOptions{
		zabbixEndpoint: *zabbixEndpoint,
		wazuhEndpoint:  *wazuhEndpoint,
		wazuhInsecure:  *wazuhInsecure,
		rtEndpoint:     *rtEndpoint,
	})
	if err != nil {
		fmt.Fprintf(stderr, "sroiaaa-broker-exec: %v\n", err)
		return 2
	}
	executor, err := connector.NewExecutor(connectors...)
	if err != nil {
		fmt.Fprintf(stderr, "sroiaaa-broker-exec: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := executor.Execute(ctx, plan)
	if err != nil {
		fmt.Fprintf(stderr, "sroiaaa-broker-exec: execute: %v\n", err)
		return 1
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "sroiaaa-broker-exec: encode result: %v\n", err)
		return 1
	}
	return 0
}

// decodePlan reads a route plan with the same strictness the broker applies to
// its own inputs: unknown fields and trailing JSON values are rejected.
func decodePlan(r io.Reader) (broker.RoutePlan, error) {
	decoder := json.NewDecoder(io.LimitReader(r, 65536))
	decoder.DisallowUnknownFields()

	var plan broker.RoutePlan
	if err := decoder.Decode(&plan); err != nil {
		return broker.RoutePlan{}, fmt.Errorf("decode route plan: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return broker.RoutePlan{}, fmt.Errorf("multiple JSON values are not allowed")
		}
		return broker.RoutePlan{}, err
	}
	if len(plan.Steps) == 0 {
		return broker.RoutePlan{}, fmt.Errorf("route plan contains no steps")
	}
	return plan, nil
}

// verifyPlan requires the plan to be one the policy would have produced.
func verifyPlan(policyPath string, plan broker.RoutePlan) error {
	policyFile, err := os.Open(policyPath)
	if err != nil {
		return fmt.Errorf("open policy: %w", err)
	}
	defer policyFile.Close()

	policy, err := broker.LoadPolicy(policyFile)
	if err != nil {
		return err
	}
	router, err := broker.NewRouter(policy)
	if err != nil {
		return err
	}
	if err := router.Verify(plan); err != nil {
		return fmt.Errorf("plan rejected: %w", err)
	}
	return nil
}

// connectorOptions carries operator-supplied execution details. Nothing here
// is derived from the route plan.
type connectorOptions struct {
	zabbixEndpoint string
	wazuhEndpoint  string
	wazuhInsecure  bool
	rtEndpoint     string
}

// buildConnectors constructs only the connectors this plan actually needs, so
// an operator can run a Zabbix plan without holding Wazuh credentials.
func buildConnectors(plan broker.RoutePlan, options connectorOptions) ([]connector.Connector, error) {
	needed := make(map[broker.Source]bool)
	for _, step := range plan.Steps {
		needed[step.Source] = true
	}

	var built []connector.Connector
	if needed[broker.SourceZabbixAPI] {
		if options.zabbixEndpoint == "" {
			return nil, fmt.Errorf("plan needs Zabbix: set -zabbix-endpoint or %s", zabbixEndpointEnv)
		}
		token := os.Getenv(zabbixTokenEnv)
		if token == "" {
			return nil, fmt.Errorf("plan needs Zabbix: %s is not set (note that a value in ~/.bashrc must also be exported)", zabbixTokenEnv)
		}
		zabbix, err := connector.NewZabbixConnector(connector.ZabbixConfig{
			Endpoint: options.zabbixEndpoint,
			Token:    token,
		})
		if err != nil {
			return nil, err
		}
		built = append(built, zabbix)
	}

	if needed[broker.SourceWazuhAPI] {
		if options.wazuhEndpoint == "" {
			return nil, fmt.Errorf("plan needs Wazuh: set -wazuh-endpoint or %s", wazuhEndpointEnv)
		}
		username := os.Getenv(wazuhUsernameEnv)
		password := os.Getenv(wazuhPasswordEnv)
		if username == "" || password == "" {
			return nil, fmt.Errorf("plan needs Wazuh: %s and %s must both be set and exported", wazuhUsernameEnv, wazuhPasswordEnv)
		}
		wazuh, err := connector.NewWazuhConnector(connector.WazuhConfig{
			Endpoint:           options.wazuhEndpoint,
			Username:           username,
			Password:           password,
			InsecureSkipVerify: options.wazuhInsecure,
		})
		if err != nil {
			return nil, err
		}
		built = append(built, wazuh)
	}

	if needed[broker.SourcePegasusDB] {
		dsn := os.Getenv(pegasusDSNEnv)
		if dsn == "" {
			return nil, fmt.Errorf("plan needs the accounting database: %s must be set and exported", pegasusDSNEnv)
		}
		pegasus, err := connector.NewPegasusConnector(connector.PegasusConfig{DSN: dsn, MaxRows: pegasusMaxRows(), MaxBytes: pegasusMaxBytes()})
		if err != nil {
			return nil, err
		}
		built = append(built, pegasus)
	}

	if needed[broker.SourceRequestTracker] {
		if options.rtEndpoint == "" {
			return nil, fmt.Errorf("plan needs RT: set -rt-endpoint or %s", rtEndpointEnv)
		}
		token := os.Getenv(rtTokenEnv)
		if token == "" {
			return nil, fmt.Errorf("plan needs RT: %s is not set (note that a value in ~/.bashrc must also be exported)", rtTokenEnv)
		}
		rt, err := connector.NewRTConnector(connector.RTConfig{
			Endpoint: options.rtEndpoint,
			Token:    token,
			Queues:   splitList(os.Getenv(rtQueuesEnv)),
		})
		if err != nil {
			return nil, err
		}
		built = append(built, rt)
	}

	for source := range needed {
		switch source {
		case broker.SourceZabbixAPI, broker.SourceWazuhAPI, broker.SourcePegasusDB, broker.SourceRequestTracker:
		default:
			return nil, fmt.Errorf("no connector implemented for source %q", source)
		}
	}
	return built, nil
}

// splitList parses a comma-separated environment value, discarding blanks so
// a trailing comma or a stray space does not become a queue name that
// matches nothing.
func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// pegasusMaxRows reads the row cap override, falling back to the connector's
// default when unset or unparseable.
func pegasusMaxRows() int {
	value := os.Getenv(pegasusMaxRowsEnv)
	if value == "" {
		return 0
	}
	rows, err := strconv.Atoi(value)
	if err != nil || rows <= 0 {
		return 0
	}
	return rows
}

// pegasusMaxBytes reads the evidence byte-cap override, falling back to the
// connector default when unset. Raise it only alongside a model whose context
// window can hold the result.
func pegasusMaxBytes() int {
	value := os.Getenv(pegasusMaxBytesEnv)
	if value == "" {
		return 0
	}
	size, err := strconv.Atoi(value)
	if err != nil || size <= 0 {
		return 0
	}
	return size
}
