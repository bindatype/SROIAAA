package zoom

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewRejectsUnusableConfigs(t *testing.T) {
	cases := map[string]Config{
		"no url":         {Token: "t"},
		"no credential":  {URL: "https://example.com/hook"},
		"plaintext http": {URL: "http://example.com/hook", Token: "t"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// A token connection sends the token verbatim; a signed connection must never
// put the secret on the wire at all.
func TestPostAuthorization(t *testing.T) {
	t.Run("token", func(t *testing.T) {
		var got string
		server := recorder(t, func(r *http.Request, _ []byte) { got = r.Header.Get("Authorization") })
		defer server.Close()
		client := dial(t, Config{URL: server.URL, Token: "tok-123"})
		if err := client.Post(context.Background(), "hello"); err != nil {
			t.Fatal(err)
		}
		if got != "tok-123" {
			t.Fatalf("Authorization = %q", got)
		}
	})

	t.Run("signature", func(t *testing.T) {
		var header, timestamp string
		var body []byte
		server := recorder(t, func(r *http.Request, b []byte) {
			header = r.Header.Get("Authorization")
			timestamp = r.Header.Get("X-Zm-Request-Timestamp")
			body = b
		})
		defer server.Close()
		client := dial(t, Config{URL: server.URL, Secret: "shhh"})
		client.now = func() time.Time { return time.Unix(1756500000, 0) }
		if err := client.Post(context.Background(), "hello"); err != nil {
			t.Fatal(err)
		}
		if timestamp != "1756500000" {
			t.Fatalf("timestamp = %q", timestamp)
		}
		mac := hmac.New(sha256.New, []byte("shhh"))
		fmt.Fprintf(mac, "v0:%s:%s", timestamp, body)
		if want := "v0=" + hex.EncodeToString(mac.Sum(nil)); header != want {
			t.Fatalf("Authorization = %q, want %q", header, want)
		}
		if strings.Contains(header, "shhh") {
			t.Fatal("secret appeared on the wire")
		}
	})
}

func TestPostReportsServerRejection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"message":"Invalid token"}`)
	}))
	defer server.Close()
	client := dial(t, Config{URL: server.URL, Token: "wrong"})
	err := client.Post(context.Background(), "hello")
	if err == nil {
		t.Fatal("expected an error")
	}
	// The operator needs Zoom's own explanation, not just a status code.
	if !strings.Contains(err.Error(), "Invalid token") {
		t.Fatalf("error lost the server's explanation: %v", err)
	}
}

// A digest longer than one Zoom message must arrive in full rather than being
// rejected whole, and each part must say where it sits in the sequence.
func TestPostSplitsLongText(t *testing.T) {
	var posted []string
	server := recorder(t, func(_ *http.Request, b []byte) {
		var payload struct {
			Content string `json:"content"`
		}
		if err := json.Unmarshal(b, &payload); err != nil {
			t.Error(err)
		}
		posted = append(posted, payload.Content)
	})
	defer server.Close()

	line := strings.Repeat("x", 200) + "\n"
	text := strings.Repeat(line, 40) // ~8KB, three messages
	if err := dial(t, Config{URL: server.URL, Token: "t"}).Post(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	if len(posted) < 2 {
		t.Fatalf("expected a split, got %d message(s)", len(posted))
	}
	for i, chunk := range posted {
		if len(chunk) > maxMessageBytes+32 {
			t.Fatalf("part %d is %d bytes", i+1, len(chunk))
		}
		if !strings.HasPrefix(chunk, fmt.Sprintf("(%d/%d)", i+1, len(posted))) {
			t.Fatalf("part %d is unlabelled: %.20q", i+1, chunk)
		}
	}
}

// A single line with no break to split on must still be sent, not dropped.
func TestSplitCutsAnOverlongLine(t *testing.T) {
	chunks := split(strings.Repeat("y", maxMessageBytes*2+10), maxMessageBytes)
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	if joined := strings.Join(chunks, ""); len(joined) != maxMessageBytes*2+10 {
		t.Fatalf("content lost: %d bytes survived", len(joined))
	}
}

func TestPostRefusesEmpty(t *testing.T) {
	if err := dial(t, Config{URL: "https://example.com/h", Token: "t"}).Post(context.Background(), "   "); err == nil {
		t.Fatal("expected an error")
	}
}

func recorder(t *testing.T, inspect func(*http.Request, []byte)) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		inspect(r, body)
		w.WriteHeader(http.StatusOK)
	}))
}

func dial(t *testing.T, cfg Config) *Client {
	t.Helper()
	cfg.HTTPClient = &http.Client{Transport: &http.Transport{
		TLSClientConfig: insecureTLS(),
	}}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
