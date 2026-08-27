package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
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

	// defaultModel matched the larger models on routing and accuracy at a
	// fraction of their latency in the 2026-08-27 model survey.
	defaultModel = "qwen3.6:35b"
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
	timeout := flags.Duration("timeout", 180*time.Second, "overall timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" || *model == "" {
		fmt.Fprintln(stderr, "sroiaaa-chat: -policy is required")
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
		})
		if err != nil {
			return nil, err
		}
		connectors = append(connectors, wazuh)
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
