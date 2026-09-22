package quota

import (
	"bytes"
	"encoding/json"
	"strings"
)

// usageKeys are the JSON keys that introduce an LLM usage report. Gemini's native
// API nests its counters under usageMetadata rather than usage.
var usageKeys = [][]byte{
	[]byte(`"usage"`),
	[]byte(`"usageMetadata"`),
}

// maxUsageObject bounds how many bytes of the previous write are retained so a
// usage block straddling two writes can still be reassembled. Provider usage
// blocks are a few hundred bytes at most.
const maxUsageObject = 4096

// modelKeys name the field carrying the model that served a request. Gemini uses
// modelVersion, OpenAI and Anthropic use model.
var modelKeys = [][]byte{
	[]byte(`"modelVersion"`),
	[]byte(`"model"`),
}

// usagePayload covers the three field namings in use: OpenAI-compatible
// (prompt_tokens / completion_tokens), Anthropic (input_tokens / output_tokens) and
// Gemini native (promptTokenCount / candidatesTokenCount).
type usagePayload struct {
	PromptTokens     uint64 `json:"prompt_tokens"`
	CompletionTokens uint64 `json:"completion_tokens"`

	InputTokens  uint64 `json:"input_tokens"`
	OutputTokens uint64 `json:"output_tokens"`

	PromptTokenCount     uint64 `json:"promptTokenCount"`
	CandidatesTokenCount uint64 `json:"candidatesTokenCount"`

	// ThoughtsTokenCount is Gemini's reasoning budget. Unlike OpenAI, which folds
	// reasoning into completion_tokens, and Anthropic, which folds thinking into
	// output_tokens, Gemini reports it *separately* from candidatesTokenCount and
	// still bills it at the output rate. Ignoring it undercounted a real
	// gemini-3.6-flash call by 95%: 503 tokens billed, 26 recorded.
	ThoughtsTokenCount uint64 `json:"thoughtsTokenCount"`

	// Totals, used only to catch categories this struct does not know about.
	TotalTokens     uint64 `json:"total_tokens"`
	TotalTokenCount uint64 `json:"totalTokenCount"`
}

// Accumulator extracts LLM token usage from a response as it streams past, without
// buffering the body.
//
// Providers report usage in incompatible shapes. OpenAI-compatible APIs emit one
// complete block, either at the top level of a unary response or in the final SSE
// chunk. Anthropic splits it: input_tokens arrive in message_start and output_tokens
// in message_delta, where the count is cumulative for the message. Gemini repeats a
// cumulative usageMetadata block in every chunk. Keeping the highest value seen for
// each counter is correct for all three, and is idempotent, so a block re-read
// across writes cannot be double-counted.
//
// The zero value is ready to use.
type Accumulator struct {
	carry            []byte
	promptTokens     uint64
	completionTokens uint64
	found            bool

	// model is the first model name seen. First wins because every provider
	// announces it before generating anything, whereas the generated text that
	// follows is attacker-influenced and could contain a convincing-looking
	// "model" field of its own.
	model string
}

// Observe feeds the next chunk of response body to the accumulator. It keeps a
// bounded tail of what it has already seen, so a usage block split across two
// writes is still scanned as a contiguous whole.
func (a *Accumulator) Observe(chunk []byte) {
	if len(chunk) == 0 {
		return
	}

	a.carry = append(a.carry, chunk...)
	a.scan(a.carry)
	a.scanModel(a.carry)

	if len(a.carry) > maxUsageObject {
		n := copy(a.carry, a.carry[len(a.carry)-maxUsageObject:])
		a.carry = a.carry[:n]
	}
}

// Result returns the highest prompt and completion counts observed so far.
func (a *Accumulator) Result() (prompt, completion uint64, found bool) {
	return a.promptTokens, a.completionTokens, a.found
}

// Model reports the model that served the request, or "" when none was seen.
// A name this deployment prices explicitly selects that price; anything else
// falls back to the route default, so a misread can never invent a wild cost.
func (a *Accumulator) Model() string {
	return a.model
}

// scan walks every usage block in b and folds it into the counters.
func (a *Accumulator) scan(b []byte) {
	for _, key := range usageKeys {
		rest := b
		for {
			i := bytes.Index(rest, key)
			if i < 0 {
				break
			}
			rest = rest[i+len(key):]

			// A truncated block is simply skipped: it stays in carry and a
			// later write completes it.
			if obj, ok := balancedObject(rest); ok {
				a.apply(obj)
			}
		}
	}
}

// scanModel records the first model name in the stream.
func (a *Accumulator) scanModel(b []byte) {
	if a.model != "" {
		return
	}
	for _, key := range modelKeys {
		i := bytes.Index(b, key)
		if i < 0 {
			continue
		}
		if name, ok := stringValue(b[i+len(key):]); ok && name != "" {
			a.model = name
			return
		}
	}
}

// stringValue reads the JSON string that follows a key, so `: "gpt-5"` yields
// gpt-5. It reports false on anything that is not a complete string, including a
// value still being streamed.
func stringValue(b []byte) (string, bool) {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	if i >= len(b) || b[i] != ':' {
		return "", false
	}
	i++
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	if i >= len(b) || b[i] != '"' {
		return "", false
	}
	i++

	start := i
	for i < len(b) {
		switch b[i] {
		case '\\':
			// A model name has no business containing an escape; bail rather than
			// decode, so this stays a fast scan and never a JSON parser.
			return "", false
		case '"':
			return string(b[start:i]), true
		}
		i++
	}
	return "", false
}

func (a *Accumulator) apply(obj []byte) {
	var u usagePayload
	if err := json.Unmarshal(obj, &u); err != nil {
		return
	}

	prompt := max(u.PromptTokens, u.InputTokens, u.PromptTokenCount)
	completion := max(u.CompletionTokens, u.OutputTokens, u.CandidatesTokenCount+u.ThoughtsTokenCount)

	// The provider's own total is authoritative: it is what they bill, and it
	// already contains every category, including ones this struct has never heard
	// of. Deriving the completion from it rather than from the named fields means
	// the next exotic counter a provider invents is charged automatically instead
	// of silently dropped -- which is exactly how Gemini's thoughtsTokenCount went
	// unbilled and undercounted a real call by 95%.
	//
	// The named fields remain the fallback for providers that report no total at
	// all, such as Anthropic's message_delta, which carries only output_tokens.
	if total := max(u.TotalTokens, u.TotalTokenCount); total > prompt {
		completion = total - prompt
	}

	if prompt > a.promptTokens {
		a.promptTokens = prompt
		a.found = true
	}
	if completion > a.completionTokens {
		a.completionTokens = completion
		a.found = true
	}
}

// balancedObject returns the JSON object following a key, from its opening brace to
// the matching closing brace. It reports false when no object follows or when the
// object is truncated.
func balancedObject(b []byte) ([]byte, bool) {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r' || b[i] == ':') {
		i++
	}
	if i >= len(b) || b[i] != '{' {
		return nil, false
	}

	depth := 0
	inString := false
	escaped := false

	for j := i; j < len(b); j++ {
		switch c := b[j]; {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
			// Braces inside a string are not structural.
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return b[i : j+1], true
			}
		}
	}

	return nil, false
}

// ExtractUsageFromJSON parses prompt and completion token counts out of a complete
// LLM JSON payload.
func ExtractUsageFromJSON(body []byte) (uint64, uint64, bool) {
	var acc Accumulator
	acc.scan(body)
	return acc.Result()
}

// ExtractUsageFromSSELine parses token usage from a single SSE line (`data: {...}`).
func ExtractUsageFromSSELine(line string) (uint64, uint64, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "data:") {
		return 0, 0, false
	}
	return ExtractUsageFromJSON([]byte(strings.TrimPrefix(trimmed, "data:")))
}
