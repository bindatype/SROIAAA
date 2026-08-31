package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/maclach/sroiaaa/internal/broker"
	"github.com/maclach/sroiaaa/internal/connector"
	"github.com/maclach/sroiaaa/internal/orchestrator"
)

const (
	mindrouterEndpointEnv = "SROIAAA_MINDROUTER_ENDPOINT"
	mindrouterKeyEnv      = "MINDROUTER_API_KEY"
	zabbixEndpointEnv     = "SROIAAA_ZABBIX_ENDPOINT"
	zabbixTokenEnv        = "ZABBIX_RO_TOKEN"
	wazuhEndpointEnv      = "SROIAAA_WAZUH_ENDPOINT"
	wazuhUsernameEnv      = "WAZUH_API_USERNAME"
	wazuhPasswordEnv      = "WAZUH_API_PASSWORD"
	// wazuhCriticalGroupsEnv names the agent groups whose loss is escalated, as
	// a comma-separated list. Site configuration, so it lives here rather than
	// in the connector: at RTS it is "RTS_Ops,Viper".
	wazuhCriticalGroupsEnv = "SROIAAA_WAZUH_CRITICAL_GROUPS"
	pegasusDSNEnv          = "SROIAAA_PEGASUS_DSN"
	pegasusMaxRowsEnv      = "SROIAAA_PEGASUS_MAX_ROWS"
	pegasusMaxBytesEnv     = "SROIAAA_PEGASUS_MAX_BYTES"
	auditPathEnv           = "SROIAAA_BROKER_AUDIT"

	// defaultModel is chosen by scripts/eval_headtohead.py, which grades six
	// question shapes rather than one: an aggregate, a grouped result that
	// engages the row cap, a two-step schema lookup, a question with no data
	// source that must be refused, a concept with no matching column that must
	// be derived rather than refused, and a listing that exceeds the cap.
	//
	// On 2026-08-28, gemma4:31b scored 30/30 at 9.8s per question against
	// llama3.3's 28/30 at 15.2s. Earlier single-question comparisons could not
	// separate them; the concept case did.
	//
	// Do not change this without rerunning that suite. Override per call with
	// -model.
	defaultModel = "gemma4:31b"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sroiaaa-chat", flag.ContinueOnError)
	flags.SetOutput(stderr)
	policyPath := flags.String("policy", "", "path to a broker policy JSON file")
	// Prefer a MindRouter alias here once one exists, so the client contract is
	// the role rather than a specific model.
	model := flags.String("model", defaultModel, "model or alias to ask")
	endpoint := flags.String("mindrouter-endpoint", os.Getenv(mindrouterEndpointEnv), "MindRouter base URL")
	zabbixEndpoint := flags.String("zabbix-endpoint", os.Getenv(zabbixEndpointEnv), "Zabbix JSON-RPC endpoint URL")
	wazuhEndpoint := flags.String("wazuh-endpoint", os.Getenv(wazuhEndpointEnv), "Wazuh API base URL")
	wazuhInsecure := flags.Bool("wazuh-insecure", false, "skip TLS verification for the Wazuh API")
	showTrace := flags.Bool("trace", false, "print the policy decision trace to stderr")
	auditPath := flags.String("audit", os.Getenv(auditPathEnv), "append a JSON-lines audit record for each question")
	timeout := flags.Duration("timeout", 180*time.Second, "overall timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	// Two separate failures, because a message naming the wrong flag sends the
	// operator to fix something that was never wrong.
	if *policyPath == "" {
		fmt.Fprintln(stderr, "sroiaaa-chat: -policy is required")
		return 2
	}
	if *model == "" {
		fmt.Fprintln(stderr, "sroiaaa-chat: -model must name a model or alias")
		return 2
	}

	question := strings.TrimSpace(strings.Join(flags.Args(), " "))
	if question == "" {
		raw, err := io.ReadAll(io.LimitReader(stdin, 8192))
		if err != nil {
			fmt.Fprintf(stderr, "sroiaaa-chat: read question: %v\n", err)
			return 1
		}
		question = strings.TrimSpace(string(raw))
	}
	if question == "" {
		fmt.Fprintln(stderr, "sroiaaa-chat: no question supplied")
		return 2
	}

	session, err := buildSession(*policyPath, *model, *endpoint, *zabbixEndpoint, *wazuhEndpoint, *wazuhInsecure)
	if err != nil {
		fmt.Fprintf(stderr, "sroiaaa-chat: %v\n", err)
		return 2
	}

	if *auditPath != "" {
		auditor, err := orchestrator.NewAuditor(*auditPath)
		if err != nil {
			fmt.Fprintf(stderr, "sroiaaa-chat: open audit: %v\n", err)
			return 2
		}
		defer auditor.Close()
		session = session.WithAudit(auditor, *model)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	answer, askErr := session.Ask(ctx, question)
	if *showTrace {
		for _, entry := range session.Trace() {
			verdict := "allowed"
			if !entry.Allowed {
				verdict = "DENIED"
			}
			fmt.Fprintf(stderr, "  [%s] %s %s\n", verdict, entry.Stage, entry.Detail)
		}
	}
	if askErr != nil {
		fmt.Fprintf(stderr, "sroiaaa-chat: %v\n", askErr)
		return 1
	}

	fmt.Fprintln(stdout, answer)
	return 0
}

func buildSession(policyPath, model, endpoint, zabbixEndpoint, wazuhEndpoint string, wazuhInsecure bool) (*orchestrator.Session, error) {
	policyFile, err := os.Open(policyPath)
	if err != nil {
		return nil, fmt.Errorf("open policy: %w", err)
	}
	defer policyFile.Close()

	policy, err := broker.LoadPolicy(policyFile)
	if err != nil {
		return nil, err
	}
	router, err := broker.NewRouter(policy)
	if err != nil {
		return nil, err
	}

	if endpoint == "" {
		return nil, fmt.Errorf("set -mindrouter-endpoint or %s", mindrouterEndpointEnv)
	}
	apiKey := os.Getenv(mindrouterKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("%s is not set (a value in ~/.bashrc must also be exported)", mindrouterKeyEnv)
	}
	client, err := orchestrator.NewMindRouterClient(orchestrator.MindRouterConfig{
		Endpoint: endpoint,
		APIKey:   apiKey,
		Model:    model,
	})
	if err != nil {
		return nil, err
	}

	// Every connector the model could reach is built up front, because the
	// intent it will propose is not known until it proposes one.
	var connectors []connector.Connector
	if zabbixEndpoint != "" && os.Getenv(zabbixTokenEnv) != "" {
		zabbix, err := connector.NewZabbixConnector(connector.ZabbixConfig{
			Endpoint: zabbixEndpoint,
			Token:    os.Getenv(zabbixTokenEnv),
		})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, zabbix)
	}
	if wazuhEndpoint != "" && os.Getenv(wazuhUsernameEnv) != "" && os.Getenv(wazuhPasswordEnv) != "" {
		wazuh, err := connector.NewWazuhConnector(connector.WazuhConfig{
			Endpoint:           wazuhEndpoint,
			Username:           os.Getenv(wazuhUsernameEnv),
			Password:           os.Getenv(wazuhPasswordEnv),
			InsecureSkipVerify: wazuhInsecure,
			CriticalGroups:     splitList(os.Getenv(wazuhCriticalGroupsEnv)),
		})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, wazuh)
	}
	if dsn := os.Getenv(pegasusDSNEnv); dsn != "" {
		pegasus, err := connector.NewPegasusConnector(connector.PegasusConfig{DSN: dsn, MaxRows: pegasusMaxRows(), MaxBytes: pegasusMaxBytes()})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, pegasus)
	}
	if len(connectors) == 0 {
		return nil, fmt.Errorf("no connectors configured; set Zabbix and/or Wazuh endpoints and credentials")
	}

	executor, err := connector.NewExecutor(connectors...)
	if err != nil {
		return nil, err
	}
	return orchestrator.NewSession(client, router, executor), nil
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

// splitList parses a comma-separated environment value, discarding blanks so a
// trailing comma or a stray space does not become a group name that matches
// nothing.
func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
