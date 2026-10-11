package gored

import "context"

// Role is a chat role.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message is one chat turn.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

// Usage is token accounting for one model call.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

// ChatOpts are per-call generation options.
type ChatOpts struct {
	Temperature float64
	MaxTokens   int
}

// ModelClient is the one method the objective loop needs from a model: given a
// conversation, produce the next assistant message. The runtime is model-agnostic;
// a concrete client (see package modelclient) speaks to a local OSS model served
// by goserve. Keeping this an interface is what lets the experiment swap models
// without touching the loop.
type ModelClient interface {
	Chat(ctx context.Context, msgs []Message, opts ChatOpts) (reply string, usage Usage, err error)
	// Name identifies the model for the run record and leaderboard.
	Name() string
}
