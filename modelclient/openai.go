// Package modelclient is a concrete gored.ModelClient that speaks the
// OpenAI-compatible chat-completions API a local OSS model exposes via goserve.
// Keeping it out of the root package keeps the runtime model-agnostic.
package modelclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	gored "github.com/t0ul/GORED"
)

// OpenAI is a minimal client for a /v1/chat/completions endpoint.
type OpenAI struct {
	ChatURL string
	Model   string
	client  *http.Client
}

// New builds a client for the given chat-completions URL (e.g. from
// goserve Harness.ChatURL) and model name.
func New(chatURL, model string) *OpenAI {
	return &OpenAI{ChatURL: chatURL, Model: model, client: &http.Client{Timeout: 120 * time.Second}}
}

func (c *OpenAI) Name() string { return c.Model }

type chatReq struct {
	Model       string          `json:"model"`
	Messages    []gored.Message `json:"messages"`
	Temperature float64         `json:"temperature"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
}

type chatResp struct {
	Choices []struct {
		Message gored.Message `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (c *OpenAI) Chat(ctx context.Context, msgs []gored.Message, opts gored.ChatOpts) (string, gored.Usage, error) {
	body, _ := json.Marshal(chatReq{
		Model:       c.Model,
		Messages:    msgs,
		Temperature: opts.Temperature,
		MaxTokens:   opts.MaxTokens,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ChatURL, bytes.NewReader(body))
	if err != nil {
		return "", gored.Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", gored.Usage{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", gored.Usage{}, fmt.Errorf("modelclient: %s: HTTP %d: %s", c.ChatURL, resp.StatusCode, truncate(string(data), 300))
	}
	var out chatResp
	if err := json.Unmarshal(data, &out); err != nil {
		return "", gored.Usage{}, fmt.Errorf("modelclient: decode: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", gored.Usage{}, fmt.Errorf("modelclient: no choices")
	}
	u := gored.Usage{PromptTokens: out.Usage.PromptTokens, CompletionTokens: out.Usage.CompletionTokens}
	return out.Choices[0].Message.Content, u, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
