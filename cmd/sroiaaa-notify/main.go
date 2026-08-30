// Command sroiaaa-notify posts text from standard input into a Zoom Team Chat
// channel.
//
// It deliberately does not know how to ask a question. Composing it with the
// thing that does keeps one job in one place:
//
//	sroiaaa-chat -policy "$POLICY" "how many agents are disconnected?" |
//	  sroiaaa-notify -title "Wazuh"
//
// Credentials come from the environment, as they do for every other source in
// this project, so that a webhook URL never appears in a command line, a shell
// history, or a cron table.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/maclach/sroiaaa/internal/zoom"
)

const (
	urlEnv    = "SROIAAA_ZOOM_WEBHOOK_URL"
	tokenEnv  = "SROIAAA_ZOOM_WEBHOOK_TOKEN"
	secretEnv = "SROIAAA_ZOOM_WEBHOOK_SECRET"

	// maxInput bounds what will be read from a pipe. An answer is a paragraph;
	// anything approaching this size means the upstream command failed in a way
	// that produced volume instead of an error.
	maxInput = 64 * 1024
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sroiaaa-notify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	title := flags.String("title", "", "optional bold first line")
	dryRun := flags.Bool("dry-run", false, "print the exact payload instead of posting")
	timeout := flags.Duration("timeout", 30*time.Second, "overall timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	raw, err := io.ReadAll(io.LimitReader(stdin, maxInput))
	if err != nil {
		fmt.Fprintf(stderr, "sroiaaa-notify: read: %v\n", err)
		return 1
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		// Posting an empty message would put a blank line in a channel and read
		// as a successful run. A silent upstream failure should be loud here.
		fmt.Fprintln(stderr, "sroiaaa-notify: nothing on stdin")
		return 2
	}
	if *title != "" {
		text = "**" + *title + "**\n" + text
	}

	if *dryRun {
		payload, err := zoom.Payload(text)
		if err != nil {
			fmt.Fprintf(stderr, "sroiaaa-notify: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(payload))
		return 0
	}

	client, err := zoom.New(zoom.Config{
		URL:    os.Getenv(urlEnv),
		Token:  os.Getenv(tokenEnv),
		Secret: os.Getenv(secretEnv),
	})
	if err != nil {
		fmt.Fprintf(stderr, "sroiaaa-notify: %v (set %s and %s)\n", err, urlEnv, secretEnv)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := client.Post(ctx, text); err != nil {
		fmt.Fprintf(stderr, "sroiaaa-notify: %v\n", err)
		return 1
	}
	return 0
}
