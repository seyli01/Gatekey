package quota

import "testing"

// Anthropic reports input_tokens in message_start and output_tokens in a later
// message_delta. Stopping at the first usage block loses every output token, i.e.
// the expensive half of the bill.
func TestAccumulator_AnthropicSplitUsage(t *testing.T) {
	var acc Accumulator

	acc.Observe([]byte(`event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":2145,"output_tokens":1}}}

`))
	acc.Observe([]byte(`event: content_block_delta
data: {"type":"content_block_delta","delta":{"text":"hello"}}

`))
	acc.Observe([]byte(`event: message_delta
data: {"type":"message_delta","usage":{"output_tokens":873}}

`))

	prompt, completion, found := acc.Result()
	if !found {
		t.Fatal("expected usage to be found")
	}
	if prompt != 2145 {
		t.Errorf("expected 2145 input tokens, got %d", prompt)
	}
	if completion != 873 {
		t.Errorf("expected 873 output tokens, got %d", completion)
	}
}

// A usage block can straddle two TCP writes; the carry buffer must reassemble it.
func TestAccumulator_UsageSplitAcrossWrites(t *testing.T) {
	full := `data: {"choices":[],"usage":{"prompt_tokens":15,"completion_tokens":42,"total_tokens":57}}` + "\n\n"

	for _, cut := range []int{10, 30, 45, 60, len(full) - 3} {
		var acc Accumulator
		acc.Observe([]byte(full[:cut]))
		acc.Observe([]byte(full[cut:]))

		prompt, completion, found := acc.Result()
		if !found || prompt != 15 || completion != 42 {
			t.Errorf("split at %d: got prompt=%d completion=%d found=%v", cut, prompt, completion, found)
		}
	}
}

// Replaying the same bytes must not inflate the counters.
func TestAccumulator_IsIdempotent(t *testing.T) {
	chunk := []byte(`data: {"usage":{"prompt_tokens":100,"completion_tokens":50}}` + "\n")

	var acc Accumulator
	acc.Observe(chunk)
	acc.Observe(chunk)

	prompt, completion, _ := acc.Result()
	if prompt != 100 || completion != 50 {
		t.Errorf("expected counters to stay at 100/50, got %d/%d", prompt, completion)
	}
}

// OpenAI streams many chunks and reports usage only in the last one.
func TestAccumulator_OpenAIStreamFinalChunk(t *testing.T) {
	var acc Accumulator

	for range 20 {
		acc.Observe([]byte(`data: {"choices":[{"delta":{"content":"tok"}}],"usage":null}` + "\n\n"))
	}
	if _, _, found := acc.Result(); found {
		t.Fatal("usage:null must not register as usage")
	}

	acc.Observe([]byte(`data: {"choices":[],"usage":{"prompt_tokens":31,"completion_tokens":220,"total_tokens":251}}` + "\n\n"))
	acc.Observe([]byte("data: [DONE]\n\n"))

	prompt, completion, found := acc.Result()
	if !found || prompt != 31 || completion != 220 {
		t.Errorf("got prompt=%d completion=%d found=%v", prompt, completion, found)
	}
}

// A brace inside a string value must not be mistaken for structure.
func TestBalancedObject_NestedAndQuoted(t *testing.T) {
	body := []byte(`{"usage":{"note":"a } brace","details":{"cached":7},"prompt_tokens":9,"completion_tokens":3}}`)

	prompt, completion, found := ExtractUsageFromJSON(body)
	if !found || prompt != 9 || completion != 3 {
		t.Errorf("got prompt=%d completion=%d found=%v", prompt, completion, found)
	}
}

func TestAccumulator_CarryStaysBounded(t *testing.T) {
	var acc Accumulator
	for range 100 {
		acc.Observe(make([]byte, 8192))
	}
	if len(acc.carry) > maxUsageObject {
		t.Errorf("carry grew to %d bytes, expected at most %d", len(acc.carry), maxUsageObject)
	}
}

// Gemini's native API nests cumulative counters under usageMetadata. Scanning only
// for "usage" recorded prompt tokens but never a single completion token.
func TestAccumulator_GeminiUsageMetadata(t *testing.T) {
	var acc Accumulator

	acc.Observe([]byte(`data: {"candidates":[{"content":{"parts":[{"text":"Bon"}]}}],"usageMetadata":{"promptTokenCount":32,"candidatesTokenCount":4,"totalTokenCount":36}}` + "\n\n"))
	acc.Observe([]byte(`data: {"candidates":[{"content":{"parts":[{"text":"jour"}]}}],"usageMetadata":{"promptTokenCount":32,"candidatesTokenCount":118,"totalTokenCount":150}}` + "\n\n"))

	prompt, completion, found := acc.Result()
	if !found {
		t.Fatal("expected Gemini usageMetadata to be recognized")
	}
	if prompt != 32 {
		t.Errorf("expected 32 prompt tokens, got %d", prompt)
	}
	if completion != 118 {
		t.Errorf("expected 118 completion tokens, got %d", completion)
	}
}

// Captured from a live gemini-3.6-flash call. Gemini reports its reasoning budget
// separately from candidatesTokenCount and bills it at the output rate, so
// ignoring it undercounted this exchange by 95%.
func TestExtractUsage_GeminiThoughtsAreBilled(t *testing.T) {
	const body = `{"candidates":[{"content":{"parts":[{"text":"1, 2, 3, 4, 5"}]}}],` +
		`"usageMetadata":{"promptTokenCount":13,"candidatesTokenCount":13,"totalTokenCount":503,` +
		`"promptTokensDetails":[{"modality":"TEXT","tokenCount":13}],"thoughtsTokenCount":477,` +
		`"serviceTier":"standard"}}`

	var acc Accumulator
	acc.Observe([]byte(body))

	prompt, completion, found := acc.Result()
	if !found {
		t.Fatal("usage block not found")
	}
	if prompt != 13 {
		t.Errorf("prompt = %d, want 13", prompt)
	}
	// 13 visible output tokens + 477 reasoning tokens.
	if completion != 490 {
		t.Errorf("completion = %d, want 490", completion)
	}
	if got := prompt + completion; got != 503 {
		t.Errorf("total = %d, want 503 to match the provider's own totalTokenCount", got)
	}
}

// A category this parser has never seen must still be charged, because a spend
// guard that undercounts lets the budget blow past its ceiling.
func TestExtractUsage_UnknownCategoriesAreReconciledFromTheTotal(t *testing.T) {
	const body = `{"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":50,` +
		`"someFutureTokenCount":900,"totalTokenCount":1050}}`

	var acc Accumulator
	acc.Observe([]byte(body))

	prompt, completion, found := acc.Result()
	if !found {
		t.Fatal("usage block not found")
	}
	if prompt != 100 {
		t.Errorf("prompt = %d, want 100", prompt)
	}
	if completion != 950 {
		t.Errorf("completion = %d, want 950 (1050 total minus 100 prompt)", completion)
	}
}

// The reconciliation must not disturb providers whose totals already add up.
func TestExtractUsage_OpenAITotalsAreLeftAlone(t *testing.T) {
	const body = `{"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}`

	var acc Accumulator
	acc.Observe([]byte(body))

	prompt, completion, _ := acc.Result()
	if prompt != 1000 || completion != 500 {
		t.Errorf("got %d/%d, want 1000/500", prompt, completion)
	}
}

// The provider's total is what they bill, so a counter this parser has never
// heard of must still be charged. This is the property that would have caught
// Gemini's thoughtsTokenCount before it cost 95% accuracy.
func TestExtractUsage_TotalIsAuthoritative(t *testing.T) {
	cases := []struct {
		name               string
		body               string
		prompt, completion uint64
	}{
		{
			name:       "unknown category is billed",
			body:       `{"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":50,"somethingNewTokenCount":900,"totalTokenCount":1050}}`,
			prompt:     100,
			completion: 950,
		},
		{
			name:       "openai totals already add up",
			body:       `{"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}`,
			prompt:     1000,
			completion: 500,
		},
		{
			// OpenAI folds reasoning into completion_tokens, so the total matches
			// and nothing must be added on top.
			name:       "openai reasoning is already included",
			body:       `{"usage":{"prompt_tokens":20,"completion_tokens":480,"total_tokens":500,"completion_tokens_details":{"reasoning_tokens":450}}}`,
			prompt:     20,
			completion: 480,
		},
		{
			// Anthropic's message_delta carries no total at all, so the named
			// fields have to remain the fallback.
			name:       "no total falls back to named fields",
			body:       `{"type":"message_delta","usage":{"output_tokens":873}}`,
			prompt:     0,
			completion: 873,
		},
		{
			// A malformed total below the prompt count must not underflow.
			name:       "total below prompt is ignored",
			body:       `{"usage":{"prompt_tokens":500,"completion_tokens":200,"total_tokens":100}}`,
			prompt:     500,
			completion: 200,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var acc Accumulator
			acc.Observe([]byte(tc.body))
			prompt, completion, _ := acc.Result()
			if prompt != tc.prompt || completion != tc.completion {
				t.Errorf("got %d/%d, want %d/%d", prompt, completion, tc.prompt, tc.completion)
			}
		})
	}
}

func TestAccumulator_Model(t *testing.T) {
	cases := map[string]string{
		`{"model":"gpt-5-2026-01-01","usage":{"total_tokens":10}}`:                  "gpt-5-2026-01-01",
		`{"modelVersion":"gemini-3.6-flash","usageMetadata":{"totalTokenCount":5}}`: "gemini-3.6-flash",
		`{"type":"message_start","message":{"model":"claude-opus-5"}}`:              "claude-opus-5",
		`{"usage":{"total_tokens":10}}`:                                             "",
	}
	for body, want := range cases {
		var acc Accumulator
		acc.Observe([]byte(body))
		if got := acc.Model(); got != want {
			t.Errorf("Model() = %q, want %q for %s", got, want, body)
		}
	}
}

// Generated text is attacker-influenced and can contain a convincing "model"
// field. The one the provider announced first has to win.
func TestAccumulator_ModelFirstOccurrenceWins(t *testing.T) {
	var acc Accumulator
	acc.Observe([]byte(`{"model":"gpt-5-mini","choices":[{"delta":{"content":"here is json: {\"model\":\"gpt-5\"}"}}]}`))
	if got := acc.Model(); got != "gpt-5-mini" {
		t.Errorf("Model() = %q, want the announced model gpt-5-mini", got)
	}
}

// A model name split across writes must not be recorded half-read.
func TestAccumulator_ModelSplitAcrossWrites(t *testing.T) {
	const body = `{"model":"gemini-3.6-flash","usageMetadata":{"promptTokenCount":10,"totalTokenCount":30}}`
	for cut := 1; cut < len(body); cut++ {
		var acc Accumulator
		acc.Observe([]byte(body[:cut]))
		acc.Observe([]byte(body[cut:]))
		if got := acc.Model(); got != "gemini-3.6-flash" {
			t.Fatalf("cut at %d: Model() = %q", cut, got)
		}
	}
}
