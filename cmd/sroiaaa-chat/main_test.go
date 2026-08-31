package main

import (
	"bytes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The example policy is the one `ask` falls back to, so testing against it also
// checks that the shipped default still loads.
func examplePolicy(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "configs", "broker-policy.example.json")
}

// clearEnv removes every variable buildSession reads, so a test does not pass
// or fail because of what happens to be exported on the machine running it.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		mindrouterEndpointEnv, mindrouterKeyEnv,
		zabbixEndpointEnv, zabbixTokenEnv,
		wazuhEndpointEnv, wazuhUsernameEnv, wazuhPasswordEnv, wazuhCriticalGroupsEnv,
		pegasusDSNEnv, pegasusMaxRowsEnv, pegasusMaxBytesEnv, auditPathEnv,
	} {
		t.Setenv(name, "")
	}
}

// The operator-facing failures: what a person sees when the invocation is
// wrong. Each asserts the exit status and that the message names the thing
// that is actually missing -- "-policy is required" was printed for a missing
// -model until this test existed.
func TestRunRejectsBadInvocations(t *testing.T) {
	policy := examplePolicy(t)
	tests := []struct {
		name   string
		args   []string
		stdin  string
		env    map[string]string
		status int
		says   string
	}{
		{
			name:   "no policy",
			args:   []string{"what is broken?"},
			status: 2,
			says:   "-policy is required",
		},
		{
			name:   "empty model",
			args:   []string{"-policy", policy, "-model", "", "what is broken?"},
			status: 2,
			says:   "-model",
		},
		{
			name:   "unknown flag",
			args:   []string{"-policy", policy, "-nonsense"},
			status: 2,
		},
		{
			name:   "no question in args or stdin",
			args:   []string{"-policy", policy},
			stdin:  "   \n",
			status: 2,
			says:   "no question supplied",
		},
		{
			name:   "unreadable policy",
			args:   []string{"-policy", filepath.Join(t.TempDir(), "absent.json"), "what is broken?"},
			status: 2,
			says:   "open policy",
		},
		{
			// Reached only after the question is resolved, so this also proves
			// the stdin path works: the question came from stdin, not args.
			name:   "no mindrouter endpoint",
			args:   []string{"-policy", policy},
			stdin:  "what is broken?",
			status: 2,
			says:   mindrouterEndpointEnv,
		},
		{
			name:   "endpoint without an api key",
			args:   []string{"-policy", policy, "what is broken?"},
			env:    map[string]string{mindrouterEndpointEnv: "http://mindrouter.invalid"},
			status: 2,
			says:   mindrouterKeyEnv,
		},
		{
			// A key and an endpoint are not enough: with no data source the
			// session can only answer from the model, which is the one thing
			// this project exists to prevent.
			name: "no connectors configured",
			args: []string{"-policy", policy, "what is broken?"},
			env: map[string]string{
				mindrouterEndpointEnv: "http://mindrouter.invalid",
				mindrouterKeyEnv:      "test-key",
			},
			status: 2,
			says:   "no connectors configured",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearEnv(t)
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			var stdout, stderr bytes.Buffer
			status := run(test.args, strings.NewReader(test.stdin), &stdout, &stderr)
			if status != test.status {
				t.Fatalf("status = %d, want %d (stderr: %s)", status, test.status, stderr.String())
			}
			if test.says != "" && !strings.Contains(stderr.String(), test.says) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr.String(), test.says)
			}
			if stdout.Len() != 0 {
				t.Fatalf("a failed run wrote to stdout: %q", stdout.String())
			}
		})
	}
}

func TestSplitList(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"RTS_Ops", []string{"RTS_Ops"}},
		{"RTS_Ops,Viper", []string{"RTS_Ops", "Viper"}},
		// A trailing comma or a stray space must not become a group name that
		// matches no agent and silently narrows escalation to nothing.
		{"RTS_Ops, Viper,", []string{"RTS_Ops", "Viper"}},
		{",,", nil},
	}
	for _, test := range tests {
		if got := splitList(test.in); !reflect.DeepEqual(got, test.want) {
			t.Errorf("splitList(%q) = %#v, want %#v", test.in, got, test.want)
		}
	}
}

// Both caps fall back to the connector default -- signalled by 0 -- rather than
// to a value of their own, so a typo in the environment cannot quietly raise a
// budget. Anything unparseable, negative, or zero means "use the default".
func TestPegasusCapOverrides(t *testing.T) {
	tests := []struct {
		value string
		want  int
	}{
		{"", 0},
		{"not-a-number", 0},
		{"0", 0},
		{"-5", 0},
		{"250", 250},
	}
	for _, test := range tests {
		t.Run("rows/"+test.value, func(t *testing.T) {
			t.Setenv(pegasusMaxRowsEnv, test.value)
			if got := pegasusMaxRows(); got != test.want {
				t.Fatalf("pegasusMaxRows(%q) = %d, want %d", test.value, got, test.want)
			}
		})
		t.Run("bytes/"+test.value, func(t *testing.T) {
			t.Setenv(pegasusMaxBytesEnv, test.value)
			if got := pegasusMaxBytes(); got != test.want {
				t.Fatalf("pegasusMaxBytes(%q) = %d, want %d", test.value, got, test.want)
			}
		})
	}
}
