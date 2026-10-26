package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GMWalletApp/epusdt/util/security"
	tb "gopkg.in/telebot.v3"
)

// TelegramConfig mirrors the Config JSON of a telegram channel row.
type TelegramConfig struct {
	BotToken string `json:"bot_token"`
	ChatID   int64  `json:"chat_id"`
	Proxy    string `json:"proxy"`
}

func init() {
	RegisterSender("telegram", sendTelegram)
}

// botCache caches *tb.Bot instances keyed by bot_token so we don't
// create a new Bot (and call getMe) on every notification.
var (
	botCacheMu sync.RWMutex
	botCache   = map[string]*tb.Bot{}
)

func getOrCreateBot(cfg *TelegramConfig) (*tb.Bot, error) {
	botCacheMu.RLock()
	bot, ok := botCache[cfg.BotToken]
	botCacheMu.RUnlock()
	if ok {
		return bot, nil
	}

	settings := tb.Settings{
		Token:       cfg.BotToken,
		Poller:      &tb.LongPoller{Timeout: 1 * time.Second},
		Synchronous: true,
		Offline:     true,
	}
	if cfg.Proxy != "" {
		settings.URL = cfg.Proxy
	}
	bot, err := tb.NewBot(settings)
	if err != nil {
		return nil, redactToken(err, cfg.BotToken)
	}

	botCacheMu.Lock()
	botCache[cfg.BotToken] = bot
	botCacheMu.Unlock()
	return bot, nil
}

// redactToken removes the bot token from a client-library error.
//
// The Telegram Bot API path contains the token, so a transport-level failure
// quotes a working credential; notify.Dispatch logs sender errors verbatim, which
// used to write the token into the application log on every failed delivery.
func redactToken(err error, botToken string) error {
	if err == nil {
		return nil
	}
	return errors.New(security.Redact(err.Error(), botToken))
}

// ParseTelegramConfig decodes telegram channel config and supports
// chat_id in either numeric or string form so API clients can send
// both JSON number and quoted text.
func ParseTelegramConfig(raw string) (*TelegramConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, ErrEmptyConfig
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}

	cfg := &TelegramConfig{}
	cfg.BotToken = pickFirstString(payload, "bot_token", "botToken", "bot-token")
	if cfg.BotToken == "" {
		return nil, fmt.Errorf("telegram config.bot_token required")
	}

	chatRaw, ok := pickFirstValue(payload, "chat_id", "chatId", "chat-id")
	if !ok {
		return nil, fmt.Errorf("telegram config.chat_id required")
	}
	chatID, err := parseTelegramChatID(chatRaw)
	if err != nil {
		return nil, err
	}
	cfg.ChatID = chatID

	cfg.Proxy = pickFirstString(payload, "proxy", "proxy_url", "proxyUrl")

	return cfg, nil
}

func pickFirstString(payload map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := payload[k].(string); ok {
			s := strings.TrimSpace(v)
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func pickFirstValue(payload map[string]interface{}, keys ...string) (interface{}, bool) {
	for _, k := range keys {
		if v, ok := payload[k]; ok {
			return v, true
		}
	}
	return nil, false
}

func parseTelegramChatID(v interface{}) (int64, error) {
	switch t := v.(type) {
	case float64:
		return int64(t), nil
	case json.Number:
		return t.Int64()
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, fmt.Errorf("telegram config.chat_id required")
		}
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("telegram config.chat_id invalid: %w", err)
		}
		return id, nil
	default:
		return 0, fmt.Errorf("telegram config.chat_id invalid type")
	}
}

func sendTelegram(configJSON, text string) error {
	cfg, err := ParseTelegramConfig(configJSON)
	if err != nil {
		return err
	}
	bot, err := getOrCreateBot(cfg)
	if err != nil {
		return err
	}
	_, err = bot.Send(&tb.User{ID: cfg.ChatID}, text, &tb.SendOptions{ParseMode: tb.ModeHTML})
	return redactToken(err, cfg.BotToken)
}
