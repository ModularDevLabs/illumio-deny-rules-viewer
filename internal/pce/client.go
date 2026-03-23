// Package pce wraps the Illumio PCE REST API.
package pce

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"illumio/denyrules/internal/config"
)

// pceRateLimiter enforces a maximum of 5 requests per second across all goroutines.
var (
	pceRateLimiter     chan struct{}
	pceRateLimiterOnce sync.Once
)

func getRateLimiter() chan struct{} {
	pceRateLimiterOnce.Do(func() {
		pceRateLimiter = make(chan struct{}, 1)
		pceRateLimiter <- struct{}{}
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			for range t.C {
				select {
				case pceRateLimiter <- struct{}{}:
				default:
				}
			}
		}()
	})
	return pceRateLimiter
}

// Client is an authenticated PCE HTTP client.
type Client struct {
	baseURL   string
	orgID     int
	apiKey    string
	apiSecret string
	http      *http.Client
}

// New creates a Client from the current config.
func New(cfg *config.Config) (*Client, error) {
	if cfg.PCEHost == "" || cfg.PCEAPIKey == "" || cfg.PCEAPISecret == "" {
		return nil, fmt.Errorf("PCE connection is not configured — visit /config to enter credentials")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.PCETLSVerify}, //nolint:gosec
	}
	return &Client{
		baseURL:   fmt.Sprintf("https://%s:%d/api/v2", cfg.PCEHost, cfg.PCEPort),
		orgID:     cfg.PCEOrgID,
		apiKey:    cfg.PCEAPIKey,
		apiSecret: cfg.PCEAPISecret,
		http: &http.Client{
			Timeout:   120 * time.Second,
			Transport: transport,
		},
	}, nil
}

// OrgPath returns a full URL for an org-scoped API path.
func (c *Client) OrgPath(path string) string {
	return fmt.Sprintf("%s/orgs/%d/%s", c.baseURL, c.orgID, path)
}

// HrefURL converts a PCE href to a full API URL.
func (c *Client) HrefURL(href string) string {
	return c.baseURL + href
}

// Get performs a GET request and decodes the JSON response into dst.
func (c *Client) Get(url string, dst any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	_, err = c.doWithHeaders(req, dst)
	return err
}

// GetHeaders performs a GET and returns the response headers along with decoding dst.
func (c *Client) GetHeaders(url string, dst any) (http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.doWithHeaders(req, dst)
}

// doWithHeaders executes the request and returns response headers alongside any error.
// Retries on 429, honouring the Retry-After header when present.
func (c *Client) doWithHeaders(req *http.Request, dst any) (http.Header, error) {
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
	}

	req.SetBasicAuth(c.apiKey, c.apiSecret)
	req.Header.Set("Accept", "application/json")

	log.Printf("PCE → %s %s", req.Method, req.URL)

	limiter := getRateLimiter()
	const maxRetries = 5
	backoff := 5 * time.Second

	for attempt := 0; ; attempt++ {
		<-limiter
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		start := time.Now()
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("PCE request failed: %w", err)
		}

		raw, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		if readErr != nil {
			return nil, fmt.Errorf("read response: %w", readErr)
		}

		if resp.StatusCode == 429 {
			if attempt >= maxRetries {
				return nil, fmt.Errorf("PCE rate limit exceeded after %d retries", maxRetries)
			}
			wait := backoff
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil {
					wait = time.Duration(secs)*time.Second + 500*time.Millisecond
				}
			}
			log.Printf("PCE 429 — waiting %s (attempt %d/%d)", wait, attempt+1, maxRetries)
			time.Sleep(wait)
			backoff *= 2
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body := errorBody(raw)
			log.Printf("PCE ✗ %s %s → %d (%s)\n%s", req.Method, req.URL, resp.StatusCode, elapsed, body)
			return nil, fmt.Errorf("PCE returned %d: %s", resp.StatusCode, body)
		}

		log.Printf("PCE ✓ %s %s → %d (%s)", req.Method, req.URL, resp.StatusCode, elapsed)

		if dst != nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, dst); err != nil {
				return nil, fmt.Errorf("decode response: %w", err)
			}
		}
		return resp.Header, nil
	}
}

// TestConnection makes a lightweight API call to verify credentials.
func TestConnection(cfg *config.Config) error {
	c, err := New(cfg)
	if err != nil {
		return err
	}
	return c.Get(c.OrgPath("labels")+"?max_results=1", nil)
}

func errorBody(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if strings.HasPrefix(strings.ToLower(s), "<!doctype") || strings.HasPrefix(strings.ToLower(s), "<html") {
		return "(HTML response — route not found on PCE)"
	}
	if len(s) > 800 {
		return s[:800] + "…"
	}
	return s
}

// fetchAllPages paginates through a collection endpoint using max_results/start.
func fetchAllPages[T any](c *Client, baseURL string) ([]T, error) {
	const pageSize = 500
	var all []T
	start := 0
	for {
		sep := "?"
		if strings.Contains(baseURL, "?") {
			sep = "&"
		}
		url := fmt.Sprintf("%s%smax_results=%d&start=%d", baseURL, sep, pageSize, start)
		var page []T
		if _, err := c.GetHeaders(url, &page); err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < pageSize {
			break
		}
		start += len(page)
	}
	return all, nil
}
