// Command netwatch provides a read-only operator interface to a running server.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultEndpoint = "https://127.0.0.1:8443"

type options struct {
	endpoint, caFile, tokenFile string
	machine                     bool
}

type operatorClient struct {
	http     *http.Client
	endpoint *url.URL
	token    string
}

func newClient(o options) (*operatorClient, error) {
	endpoint, err := url.Parse(o.endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return nil, errors.New("--url must be an HTTPS origin")
	}
	if o.tokenFile == "" {
		return nil, errors.New("set --token-file or NETWATCH_OPERATOR_TOKEN_FILE")
	}
	file, err := os.Open(o.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("open operator token file: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return nil, fmt.Errorf("read operator token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if len(raw) > 4096 || len(token) < 32 || strings.ContainsAny(token, " \r\n\t") {
		return nil, errors.New("operator token file must contain one valid token")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if o.caFile != "" {
		pem, err := os.ReadFile(o.caFile)
		if err != nil {
			return nil, fmt.Errorf("read trusted CA file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("trusted CA file must contain a PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &operatorClient{client, endpoint, token}, nil
}

func (c *operatorClient) get(ctx context.Context, path string, query url.Values, result any) error {
	endpoint := *c.endpoint
	endpoint.Path, endpoint.RawQuery = path, query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	if strings.HasPrefix(path, "/v1/") {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", path, resp.StatusCode)
	}
	const maxResponse = 2 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return errors.New("could not read a bounded server response")
	}
	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("invalid response from %s: %w", path, err)
	}
	return nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	usage := func() { fmt.Fprintln(stderr, "Usage: netwatch {status|doctor|incidents} [options]") }
	if len(args) == 0 {
		usage()
		return 1, nil
	}
	action := args[0]
	switch action {
	case "-h", "--help", "help":
		usage()
		return 0, nil
	case "status", "doctor", "incidents":
	default:
		usage()
		return 1, fmt.Errorf("unknown command %q", action)
	}
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := options{}
	endpoint := os.Getenv("NETWATCH_URL")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	fs.StringVar(&o.endpoint, "url", endpoint, "HTTPS origin")
	fs.StringVar(&o.caFile, "ca", os.Getenv("NETWATCH_CA_FILE"), "trusted PEM CA file")
	fs.StringVar(&o.tokenFile, "token-file", os.Getenv("NETWATCH_OPERATOR_TOKEN_FILE"), "file containing the operator token")
	fs.BoolVar(&o.machine, "json", false, "write JSON to stdout")
	var maxAge, since time.Duration
	var entity, model string
	var before int64
	if action == "doctor" {
		fs.DurationVar(&maxAge, "max-age", 30*time.Second, "maximum event age or queue age for live analysis")
	}
	if action == "incidents" {
		fs.DurationVar(&since, "since", time.Hour, "incident detection lookback, e.g. 1h or 168h")
		fs.StringVar(&entity, "entity", "", "filter by exact entity")
		fs.StringVar(&model, "model", "", "filter by exact model ID")
		fs.Int64Var(&before, "before", 0, "cursor from the previous page")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 1, nil
	}
	if fs.NArg() != 0 || (action == "doctor" && maxAge <= 0) || (action == "incidents" && (since <= 0 || before < 0)) {
		return 1, errors.New("invalid options")
	}
	client, err := newClient(o)
	if err != nil {
		return 1, err
	}
	defer client.http.CloseIdleConnections()
	if action == "incidents" {
		from := time.Now().Add(-since).UnixNano()
		query := url.Values{"from": {strconv.FormatInt(max(from, 0), 10)}, "entity": {entity}, "model": {model}}
		if before != 0 {
			query.Set("before", strconv.FormatInt(before, 10))
		}
		return 0, client.incidents(ctx, query, o.machine, stdout)
	}
	if action == "doctor" {
		return client.doctor(ctx, maxAge, o.machine, stdout)
	}
	status, err := client.status(ctx)
	if err != nil {
		return 1, err
	}
	if o.machine {
		return 0, json.NewEncoder(stdout).Encode(status)
	}
	return 0, status.print(stdout)
}

func main() {
	code, err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "netwatch:", err)
		code = 1
	}
	os.Exit(code)
}
