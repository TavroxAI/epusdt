package security

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	const token = "123456:AAHsecret"
	text := `Post "https://api.telegram.org/bot` + token + `/sendMessage": boom`

	got := Redact(text, token)
	if strings.Contains(got, token) {
		t.Fatalf("secret survived redaction: %q", got)
	}
	if !strings.Contains(got, RedactedSecret) {
		t.Fatalf("redaction placeholder missing: %q", got)
	}

	if got := Redact(text, ""); got != text {
		t.Fatalf("empty secret changed the text: %q", got)
	}
	if got := Redact(text, "  "); got != text {
		t.Fatalf("blank secret changed the text: %q", got)
	}
}
