package telegram

import "testing"

// TestIsAdminChatID covers the whitelist decision inline buttons and text
// commands share (vuln-0019).
func TestIsAdminChatID(t *testing.T) {
	original := adminChatID
	t.Cleanup(func() { adminChatID = original })

	adminChatID = 4242
	if !isAdminChatID(4242) {
		t.Fatal("the configured operator chat was rejected")
	}
	if isAdminChatID(1) {
		t.Fatal("a foreign chat was accepted")
	}

	// An unconfigured bot accepts nobody; the guard must not turn into a wildcard.
	adminChatID = 0
	if isAdminChatID(0) || isAdminChatID(4242) {
		t.Fatal("an unset admin chat authorized an update")
	}
}

func TestChatIDOfNilContext(t *testing.T) {
	if got := chatIDOf(nil); got != 0 {
		t.Fatalf("chatIDOf(nil) = %d, want 0", got)
	}
}
