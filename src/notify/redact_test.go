package notify

import (
	"errors"
	"strings"
	"testing"
)

// TestRedactTokenCoversSenderErrors covers vuln-0021: the Telegram Bot API URL
// embeds the token, so a transport error logged verbatim writes a working
// credential into the application log.
func TestRedactTokenCoversSenderErrors(t *testing.T) {
	const token = "123456789:AAHfake-token-value-for-tests"
	err := errors.New(`Post "https://api.telegram.org/bot` + token + `/sendMessage": dial tcp: connection refused`)

	redacted := redactToken(err, token)
	if redacted == nil {
		t.Fatal("redactToken returned nil")
	}
	if strings.Contains(redacted.Error(), token) {
		t.Fatalf("token still present in the error: %v", redacted)
	}
	if !strings.Contains(redacted.Error(), "<redacted>") {
		t.Fatalf("error was not redacted: %v", redacted)
	}
	// The rest of the message is kept so the failure is still diagnosable.
	if !strings.Contains(redacted.Error(), "connection refused") {
		t.Fatalf("diagnostic detail was lost: %v", redacted)
	}

	if redactToken(nil, token) != nil {
		t.Fatal("redactToken(nil) should stay nil")
	}
}
