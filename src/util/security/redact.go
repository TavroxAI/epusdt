package security

import "strings"

// RedactedSecret is what a leaked credential is replaced with in logs and error
// messages.
const RedactedSecret = "<redacted>"

// Redact removes every occurrence of secret from text.
//
// Outbound client libraries embed the credential in the URLs they report on
// failure (a Telegram bot token sits in the Bot API path, for example), so an
// error that is logged verbatim writes a working credential into the application
// log. Callers redact at the point the error is created, before any logger sees
// it.
func Redact(text, secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, RedactedSecret)
}
