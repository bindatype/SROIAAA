package zoom

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const fixedMillis = int64(1756500000000)

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

// The timestamp belongs in the query string, in milliseconds. Sent as a header
// it produced "400 Bad Request: Missed timestamp" against the live endpoint,
// which is the regression this pins.
func TestSignedRequestPutsTimestampInTheQuery(t *testing.T) {
	var got *http.Request
	var body []byte
	server := recorder(t, func(r *http.Request, b []byte) { got, body = r, b })
	defer server.Close()

	client := dial(t, Config{URL: server.URL, Secret: "shhh"})
	if err := client.Post(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}

	query := got.URL.Query()
	if query.Get("format") != "message" {
		t.Fatalf("format = %q", query.Get("format"))
	}
	if query.Get("timestamp") != strconv.FormatInt(fixedMillis, 10) {
		t.Fatalf("timestamp = %q, want milliseconds %d", query.Get("timestamp"), fixedMillis)
	}
	if got.Header.Get("X-Zm-Request-Timestamp") != "" {
		t.Fatal("timestamp must not be sent as a header")
	}

	// base64 over "{format}&{timestamp}&{message}", no scheme prefix.
	mac := hmac.New(sha256.New, []byte("shhh"))
	io.WriteString(mac, "message&"+query.Get("timestamp")+"&"+string(body))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if auth := got.Header.Get("Authorization"); auth != want {
		t.Fatalf("Authorization = %q, want %q", auth, want)
	}
	if strings.Contains(got.Header.Get("Authorization"), "v0=") {
		t.Fatal("Authorization must not carry a scheme prefix")
	}
}

// For format=message the body is a JSON string literal, not an object.
func TestBodyIsAJSONStringLiteral(t *testing.T) {
	var body []byte
	server := recorder(t, func(_ *http.Request, b []byte) { body = b })
	defer server.Close()
	if err := dial(t, Config{URL: server.URL, Token: "t"}).Post(context.Background(), `say "hi"`); err != nil {
		t.Fatal(err)
	}
	if body[0] != '"' {
		t.Fatalf("body is not a string literal: %s", body)
	}
	var decoded string
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %s", body)
	}
	if decoded != `say "hi"` {
		t.Fatalf("round trip lost content: %q", decoded)
	}
}

// A token connection sends the token verbatim and no timestamp.
func TestTokenRequest(t *testing.T) {
	var got *http.Request
	server := recorder(t, func(r *http.Request, _ []byte) { got = r })
	defer server.Close()
	if err := dial(t, Config{URL: server.URL, Token: "tok-123"}).Post(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	if got.Header.Get("Authorization") != "tok-123" {
		t.Fatalf("Authorization = %q", got.Header.Get("Authorization"))
	}
	if got.URL.Query().Get("timestamp") != "" {
		t.Fatal("unsigned requests carry no timestamp")
	}
}

// Each variant must produce a different signature, or the probe cannot tell
// them apart and would report every one as accepted.
func TestVariantsAreDistinct(t *testing.T) {
	body, _ := json.Marshal("hello")
	seen := map[string]string{}
	for _, v := range Variants {
		sig := Sign("shhh", "message", "1756500000000", "hello", body, v)
		if prior, dup := seen[sig]; dup {
			t.Fatalf("%s and %s produce the same signature", prior, v.Name)
		}
		seen[sig] = v.Name
	}
}

func TestVariantByName(t *testing.T) {
	v, err := VariantByName("plain-text/urlsafe")
	if err != nil || v == nil || v.HashRawBody || !v.URLSafe {
		t.Fatalf("resolved wrongly: %+v %v", v, err)
	}
	if _, err := VariantByName("nonsense"); err == nil {
		t.Fatal("expected an error naming the valid variants")
	}
	if v, err := VariantByName(""); v != nil || err != nil {
		t.Fatal("empty must mean the default, not an error")
	}
}

// An existing query string on the webhook URL must survive.
func TestPreservesExistingQuery(t *testing.T) {
	var got *http.Request
	server := recorder(t, func(r *http.Request, _ []byte) { got = r })
	defer server.Close()
	client := dial(t, Config{URL: server.URL + "?tenant=gwu", Token: "t"})
	if err := client.Post(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	if got.URL.Query().Get("tenant") != "gwu" {
		t.Fatalf("lost the original query: %s", got.URL.RawQuery)
	}
}

func TestPostReportsServerRejection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "Missed timestamp")
	}))
	defer server.Close()
	err := dial(t, Config{URL: server.URL, Secret: "s"}).Post(context.Background(), "hello")
	if err == nil || !strings.Contains(err.Error(), "Missed timestamp") {
		t.Fatalf("error lost the server's explanation: %v", err)
	}
}

// Probe must report the variant the server accepts, and must group variants
// whose signatures are byte-identical rather than counting them separately.
func TestProbeIdentifiesTheAcceptedVariant(t *testing.T) {
	want := Variants[2] // plain-text/standard
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var text string
		json.Unmarshal(body, &text)
		if r.Header.Get("Authorization") != Sign("shhh", "message", r.URL.Query().Get("timestamp"), text, body, want) {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "bad signature")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	results, err := dial(t, Config{URL: server.URL, Secret: "shhh"}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var accepted []ProbeResult
	for _, r := range results {
		if r.Accepted {
			accepted = append(accepted, r)
		}
	}
	if len(accepted) != 1 {
		t.Fatalf("%d results accepted, want 1: %+v", len(accepted), results)
	}
	var named bool
	for _, name := range accepted[0].Variants {
		named = named || name == want.Name
	}
	if !named {
		t.Fatalf("accepted group %v does not name %s", accepted[0].Variants, want.Name)
	}
}

// Two constructions that produce the same bytes must cost one request, not two.
func TestProbeGroupsIdenticalSignatures(t *testing.T) {
	var requests int
	server := recorder(t, func(*http.Request, []byte) { requests++ })
	defer server.Close()
	results, err := dial(t, Config{URL: server.URL, Secret: "shhh"}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	grouped := 0
	for _, r := range results {
		grouped += len(r.Variants)
	}
	if grouped != len(Variants) {
		t.Fatalf("results cover %d variants, want %d", grouped, len(Variants))
	}
	if requests != len(results) {
		t.Fatalf("sent %d requests for %d distinct signatures", requests, len(results))
	}
	if requests > len(Variants) {
		t.Fatalf("sent more requests (%d) than variants (%d)", requests, len(Variants))
	}
}

func TestProbeNeedsASecret(t *testing.T) {
	if _, err := dial(t, Config{URL: "https://example.com/h", Token: "t"}).Probe(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

// Describe must show the real request and send nothing.
func TestDescribeSendsNothing(t *testing.T) {
	calls := 0
	server := recorder(t, func(*http.Request, []byte) { calls++ })
	defer server.Close()
	out, err := dial(t, Config{URL: server.URL, Secret: "shhh"}).Describe("hello")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("Describe sent %d request(s)", calls)
	}
	for _, want := range []string{"format=message", "timestamp=" + strconv.FormatInt(fixedMillis, 10), "Authorization:", `"hello"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("description omits %q:\n%s", want, out)
		}
	}
}

func TestPostSplitsLongText(t *testing.T) {
	var posted []string
	server := recorder(t, func(_ *http.Request, b []byte) {
		var text string
		if err := json.Unmarshal(b, &text); err != nil {
			t.Error(err)
		}
		posted = append(posted, text)
	})
	defer server.Close()

	text := strings.Repeat(strings.Repeat("x", 200)+"\n", 40) // ~8KB
	if err := dial(t, Config{URL: server.URL, Token: "t"}).Post(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	if len(posted) < 2 {
		t.Fatalf("expected a split, got %d", len(posted))
	}
	for i, chunk := range posted {
		if len(chunk) > maxMessageBytes+32 {
			t.Fatalf("part %d is %d bytes", i+1, len(chunk))
		}
		if !strings.HasPrefix(chunk, "("+strconv.Itoa(i+1)+"/"+strconv.Itoa(len(posted))+")") {
			t.Fatalf("part %d unlabelled: %.20q", i+1, chunk)
		}
	}
}

func TestSplitCutsAnOverlongLine(t *testing.T) {
	chunks := split(strings.Repeat("y", maxMessageBytes*2+10), maxMessageBytes)
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	if joined := strings.Join(chunks, ""); len(joined) != maxMessageBytes*2+10 {
		t.Fatalf("content lost: %d bytes", len(joined))
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
	if _, err := url.Parse(cfg.URL); err != nil {
		t.Fatal(err)
	}
	cfg.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: insecureTLS()}}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.UnixMilli(fixedMillis) }
	return client
}
