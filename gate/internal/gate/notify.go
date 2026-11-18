package gate

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	telegramAPI     = "https://api.telegram.org"
	telegramTimeout = 15 * time.Second
	notifyQueue     = 32
)

// Telegram sends events through the Bot API from a background goroutine;
// Notify drops events when the queue is full rather than block a request.
type Telegram struct {
	api    string
	token  string
	chatID string
	client *http.Client
	queue  chan Event
	log    *slog.Logger
}

// NewTelegram reads the bot token from cfg.TokenFile and starts the sender.
func NewTelegram(cfg *TelegramConfig, log *slog.Logger) (*Telegram, error) {
	raw, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("read telegram token: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, "/?#") {
		return nil, fmt.Errorf("telegram token in %s is malformed", cfg.TokenFile)
	}
	t := &Telegram{
		api:    telegramAPI,
		token:  token,
		chatID: cfg.ChatID,
		client: &http.Client{Timeout: telegramTimeout},
		queue:  make(chan Event, notifyQueue),
		log:    log,
	}
	go t.run()
	return t, nil
}

func (t *Telegram) Notify(e Event) {
	select {
	case t.queue <- e:
	default:
		t.log.Warn("notification dropped", "event", e.Kind)
	}
}

// FormatEvent is the whole notification text: no addresses, no secrets.
func FormatEvent(e Event) string {
	return fmt.Sprintf("[%s] %s: %s — %s", e.Gate, e.Client, e.Kind, e.Detail)
}

func (t *Telegram) run() {
	for e := range t.queue {
		if err := t.send(FormatEvent(e)); err != nil {
			// The error text never includes the token: send strips it.
			t.log.Warn("telegram send failed", "event", e.Kind, "err", err)
		}
	}
}

func (t *Telegram) send(text string) error {
	ctx, cancel := context.WithTimeout(context.Background(), telegramTimeout)
	defer cancel()
	form := url.Values{"chat_id": {t.chatID}, "text": {text}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.api+"/bot"+t.token+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.client.Do(req)
	if err != nil {
		// *url.Error embeds the URL, which contains the token.
		return fmt.Errorf("request failed: %s", strings.ReplaceAll(err.Error(), t.token, "<token>"))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// LogNotifier only logs; used when Telegram is not configured.
type LogNotifier struct{ Log *slog.Logger }

func (n LogNotifier) Notify(e Event) {
	n.Log.Info("notify", "event", e.Kind, "client", e.Client, "detail", e.Detail)
}
