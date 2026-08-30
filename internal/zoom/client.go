// Package zoom posts messages into a Zoom Team Chat channel through an
// incoming webhook.
//
// The direction is one way, and the name is written from Zoom's point of view:
// an "incoming webhook" is incoming to Zoom, so this package sends and never
// receives. Reading questions out of a channel needs a Zoom Marketplace app
// with a Team Chat bot, which is a different credential, a different endpoint,
// and an inbound path from Zoom's cloud to a host we run. Nothing here gets us
// closer to that; it is deliberately the half that needs no inbound firewall
// change.
package zoom

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxMessageBytes is a conservative bound on one Zoom chat message. Zoom
// rejects an over-long message outright rather than truncating it, which for a
// digest means the whole post is lost rather than its tail, so long content is
// split here instead.
const maxMessageBytes = 3500

// Config carries the values printed by the /inc connect command in the target
// channel. Exactly one of Token or Secret is used, depending on which form of
// the command created the connection.
type Config struct {
	// URL is the endpoint /inc connect returned. It encodes which channel the
	// message lands in, so it is as sensitive as the credential beside it.
	URL string
	// Token authenticates a connection made with "/inc connect".
	Token string
	// Secret authenticates a connection made with "/inc connect -s", by signing
	// each payload rather than transmitting a shared static string. Prefer it.
	Secret string

	HTTPClient *http.Client
}

type Client struct {
	url    string
	token  string
	secret string
	http   *http.Client
	now    func() time.Time
}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("zoom: webhook URL is empty")
	}
	if !strings.HasPrefix(cfg.URL, "https://") {
		// The credential travels in a header on every call. Over plain HTTP it
		// travels in clear text to whoever is between here and Zoom.
		return nil, fmt.Errorf("zoom: webhook URL must be https")
	}
	if cfg.Token == "" && cfg.Secret == "" {
		return nil, fmt.Errorf("zoom: set either a token or a signing secret")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		url:    cfg.URL,
		token:  cfg.Token,
		secret: cfg.Secret,
		http:   client,
		now:    time.Now,
	}, nil
}

// Post sends text to the channel, splitting it when it exceeds what Zoom will
// accept in one message. A split is reported in order, and the first failure
// stops the rest: a partial digest that announces itself as partial is better
// than one that silently ends mid-sentence.
func (c *Client) Post(ctx context.Context, text string) error {
	chunks := split(text, maxMessageBytes)
	if len(chunks) == 0 {
		return fmt.Errorf("zoom: nothing to post")
	}
	for i, chunk := range chunks {
		if len(chunks) > 1 {
			chunk = fmt.Sprintf("(%d/%d)\n%s", i+1, len(chunks), chunk)
		}
		if err := c.postOne(ctx, chunk); err != nil {
			if i == 0 {
				return err
			}
			return fmt.Errorf("zoom: sent %d of %d parts: %w", i, len(chunks), err)
		}
	}
	return nil
}

func (c *Client) postOne(ctx context.Context, text string) error {
	payload, err := Payload(text)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("zoom: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.authorize(req, payload)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("zoom: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Zoom explains a rejected payload in the body, and that explanation is
		// the whole diagnostic when a format or credential is wrong.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("zoom: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// authorize applies whichever scheme the connection was created with.
//
// The signed form follows Zoom's documented v0 construction: a timestamp
// header, and an HMAC-SHA256 over "v0:{timestamp}:{body}" keyed by the secret.
// Confirm the header names against what /inc connect -s prints for this
// account before trusting it in production; if they differ it is this function
// and nothing else that changes.
func (c *Client) authorize(req *http.Request, payload []byte) {
	if c.secret == "" {
		req.Header.Set("Authorization", c.token)
		return
	}
	timestamp := strconv.FormatInt(c.now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(c.secret))
	fmt.Fprintf(mac, "v0:%s:%s", timestamp, payload)
	req.Header.Set("X-Zm-Request-Timestamp", timestamp)
	req.Header.Set("Authorization", "v0="+hex.EncodeToString(mac.Sum(nil)))
}

// Payload renders the message body Zoom expects. It is exported so that a
// dry run can show the exact bytes that would go over the wire, which is how
// the format gets confirmed without a live connection.
func Payload(text string) ([]byte, error) {
	return json.Marshal(struct {
		Markdown bool   `json:"is_markdown_support"`
		Content  string `json:"content"`
	}{Markdown: true, Content: text})
}

// split breaks text into chunks no larger than limit bytes, preferring a line
// boundary. A line longer than the limit on its own is cut, because the
// alternative is refusing to send it at all.
func split(text string, limit int) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if len(text) <= limit {
		return []string{text}
	}
	var chunks []string
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			chunks = append(chunks, strings.TrimRight(current.String(), "\n"))
			current.Reset()
		}
	}
	for _, line := range strings.Split(text, "\n") {
		for len(line) > limit {
			flush()
			chunks = append(chunks, line[:limit])
			line = line[limit:]
		}
		if current.Len()+len(line)+1 > limit {
			flush()
		}
		current.WriteString(line)
		current.WriteString("\n")
	}
	flush()
	return chunks
}
