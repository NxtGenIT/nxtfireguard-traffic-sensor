package utils

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"go.uber.org/zap"
)

type APIClient struct {
	cfg        *config.Config
	httpClient *http.Client
}

type RequestOptions struct {
	Method      string
	Endpoint    string
	Body        io.Reader
	MaxRetries  int
	InitBackoff time.Duration
}

// Creates a new API client with the given config
func NewAPIClient(cfg *config.Config) *APIClient {
	return &APIClient{
		cfg:        cfg,
		httpClient: http.DefaultClient,
	}
}

// Performs an authenticated HTTP request with retry logic
// Returns the response body and any error encountered
func (c *APIClient) DoRequest(opts RequestOptions) (*http.Response, error) {
	// Set defaults
	if opts.Method == "" {
		opts.Method = "GET"
	}
	if opts.MaxRetries == 0 {
		opts.MaxRetries = 3
	}
	if opts.InitBackoff == 0 {
		opts.InitBackoff = time.Second
	}

	url := fmt.Sprintf("%s%s", c.cfg.NfgArbiterUrl, opts.Endpoint)
	backoff := opts.InitBackoff

	zap.L().Debug("Starting API request",
		zap.String("method", opts.Method),
		zap.String("url", url),
	)

	var lastErr error
	for attempt := 0; attempt <= opts.MaxRetries; attempt++ {
		req, err := http.NewRequest(opts.Method, url, opts.Body)
		if err != nil {
			zap.L().Error("Failed to create API request",
				zap.String("url", url),
				zap.Error(err),
			)
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Set authentication headers
		req.Header.Set("X_AUTH_KEY", c.cfg.AuthSecret)
		req.Header.Set("X_SENSOR_NAME", c.cfg.SensorName)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			zap.L().Warn("API request failed, retrying",
				zap.Int("attempt", attempt+1),
				zap.Int("maxRetries", opts.MaxRetries),
				zap.String("url", url),
				zap.Error(err),
			)
			if attempt < opts.MaxRetries {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			zap.L().Error("API request failed after retries",
				zap.Int("maxRetries", opts.MaxRetries),
				zap.String("url", url),
				zap.Error(err),
			)
			return nil, fmt.Errorf("failed to fetch data after retries: %w", err)
		}

		// Success case
		if resp.StatusCode == http.StatusOK {
			zap.L().Debug("API request successful",
				zap.String("url", url),
				zap.Int("status", resp.StatusCode),
			)
			return resp, nil
		}

		// Non-200 status code
		resp.Body.Close()

		// Retry on 5xx errors
		if resp.StatusCode >= 500 && attempt < opts.MaxRetries {
			zap.L().Warn("Server error, retrying",
				zap.Int("attempt", attempt+1),
				zap.Int("maxRetries", opts.MaxRetries),
				zap.String("url", url),
				zap.Int("status", resp.StatusCode),
			)
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		// Non-retriable error
		zap.L().Error("API returned non-retriable status",
			zap.String("url", url),
			zap.Int("status", resp.StatusCode),
			zap.String("statusText", resp.Status),
		)
		return nil, fmt.Errorf("API returned status %s", resp.Status)
	}

	zap.L().Error("API request failed after all retries",
		zap.Int("maxRetries", opts.MaxRetries),
		zap.String("url", url),
	)
	return nil, fmt.Errorf("request failed after %d retries: %w", opts.MaxRetries, lastErr)
}

// Same as DoRequest but panics on error
func (c *APIClient) MustDoRequest(opts RequestOptions) *http.Response {
	resp, err := c.DoRequest(opts)
	if err != nil {
		panic(err)
	}
	return resp
}
