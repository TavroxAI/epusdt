package telegram

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/util/log"
	"github.com/GMWalletApp/epusdt/util/security"
	tb "gopkg.in/telebot.v3"
)

// bots is the single bot instance backing slash-command handlers
// (/start, WalletList, add-wallet dialog). Config is read from the
// settings table (system.telegram_bot_token + system.telegram_chat_id).
// Decoupled from notification_channels — that table drives push
// notifications only (via notify/dispatcher.go).
var (
	bots        *tb.Bot
	adminChatID int64
	reloadMu    sync.Mutex
	// adminHandlers is the whitelisted group every command and inline-button
	// handler is registered on, so the chat check cannot be forgotten for a new
	// button.
	adminHandlers *tb.Group
)

// BotStart connects the command bot. If no telegram channel is
// configured yet it logs and returns; the service otherwise runs fine
// and notifications still fan out as soon as a channel is added (those
// use their own per-request bot; see notify/telegram_sender.go).
func BotStart() {
	if err := reloadBot("bootstrap"); err != nil {
		log.Sugar.Errorf("[telegram] bot start failed: %v", err)
	}
}

// ReloadBotAsync refreshes the command bot from notification_channels.
// It is used by admin API handlers after telegram channel create/update/
// status/delete so operators don't need to restart the service.
func ReloadBotAsync(reason string) {
	go func() {
		if err := reloadBot(reason); err != nil {
			log.Sugar.Errorf("[telegram] reload failed, reason=%s err=%v", reason, err)
		}
	}()
}

// loadCommandBotConfig reads the command-bot config from the settings
// table (system.telegram_bot_token + system.telegram_chat_id).
// Returns (nil, "", nil) when the keys are absent so the caller can
// log and return gracefully — bot stays disabled until settings are set.
func loadCommandBotConfig() (*botConfig, string, error) {
	botToken := strings.TrimSpace(data.GetSettingString("system.telegram_bot_token", ""))
	chatIDStr := strings.TrimSpace(data.GetSettingString("system.telegram_chat_id", ""))
	if botToken == "" || chatIDStr == "" {
		return nil, "", nil
	}
	chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("invalid telegram chat_id in settings: %w", err)
	}
	return &botConfig{BotToken: botToken, ChatID: chatID}, "settings", nil
}

// botConfig holds the minimal fields needed to start the command bot.
type botConfig struct {
	BotToken string
	ChatID   int64
}

func reloadBot(reason string) error {
	reloadMu.Lock()
	defer reloadMu.Unlock()

	if bots != nil {
		bots.Stop()
		bots = nil
	}
	adminHandlers = nil

	cfg, source, err := loadCommandBotConfig()
	if err != nil {
		return err
	}
	if cfg == nil {
		log.Sugar.Infof("[telegram] no enabled telegram channel configured; command bot disabled (reason=%s)", reason)
		return nil
	}
	adminChatID = cfg.ChatID

	botSetting := tb.Settings{
		Token:       cfg.BotToken,
		Poller:      &tb.LongPoller{Timeout: 50 * time.Second},
		Synchronous: true,
	}
	newBot, err := tb.NewBot(botSetting)
	if err != nil {
		return fmt.Errorf("new bot: %w", redactedError(err, cfg.BotToken))
	}
	if err = newBot.SetCommands(Cmds); err != nil {
		return fmt.Errorf("set commands: %w", redactedError(err, cfg.BotToken))
	}
	bots = newBot
	RegisterHandle()
	go bots.Start()

	log.Sugar.Infof("[telegram] command bot started, reason=%s, source=%s", reason, source)
	return nil
}

// RegisterHandle wires slash-command, text-message and inline-button routes onto
// one whitelisted group.
//
// Every handler — including the wallet menu's inline buttons — must go through
// adminChatGuard: the buttons carry wallet identifiers, and a forwarded menu used
// to let a stranger disable, re-enable or delete wallet addresses because the
// inline handlers were registered on the bot instead of on the whitelisted group.
func RegisterHandle() {
	if bots == nil {
		return
	}
	admin := bots.Group()
	admin.Use(adminChatGuard())
	admin.Handle(START_CMD, WalletList)
	admin.Handle(tb.OnText, OnTextMessageHandle)
	adminHandlers = admin
}

// registerAdminInline attaches an inline-button handler to the whitelisted group.
func registerAdminInline(btn *tb.InlineButton, handler tb.HandlerFunc) {
	if bots == nil || btn == nil || adminHandlers == nil {
		return
	}
	adminHandlers.Handle(btn, handler)
}

// adminChatGuard drops any update that does not come from the configured operator
// chat. A rejected update is ignored silently: telling a stranger that the chat is
// not authorized only reveals that the bot is an admin bot.
func adminChatGuard() tb.MiddlewareFunc {
	return func(next tb.HandlerFunc) tb.HandlerFunc {
		return func(c tb.Context) error {
			if !isAdminChatID(chatIDOf(c)) {
				log.Sugar.Warnf("[telegram] rejected update from chat=%d: not the configured operator chat", chatIDOf(c))
				return nil
			}
			return next(c)
		}
	}
}

// isAdminChatID reports whether chatID is the configured operator chat.
func isAdminChatID(chatID int64) bool {
	return adminChatID != 0 && chatID == adminChatID
}

func chatIDOf(c tb.Context) int64 {
	if c == nil {
		return 0
	}
	chat := c.Chat()
	if chat == nil {
		return 0
	}
	return chat.ID
}

// redactedError strips the bot token from a client-library error before it can be
// logged: the token is part of every Bot API URL, so a transport failure quotes it.
func redactedError(err error, botToken string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", security.Redact(err.Error(), botToken))
}
