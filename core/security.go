package core

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
)

// These are set at build time via -ldflags
var EmbeddedFingerprint string = ""
var EmbeddedPasswordHash string = ""

// HashPassword creates a salted SHA-256 hash of a password
func HashPassword(password string) string {
	salt := "evilginx-cl-auth-2026"
	combined := salt + password + salt
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash)
}

// GenerateFingerprint creates a unique VPS fingerprint from machine-id + MAC addresses
func GenerateFingerprint() string {
	var parts []string

	// Read machine-id
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		mid := strings.TrimSpace(string(data))
		if mid != "" {
			parts = append(parts, mid)
		}
	}

	// Collect all physical MAC addresses (sorted for consistency)
	ifaces, err := net.Interfaces()
	if err == nil {
		var macs []string
		for _, iface := range ifaces {
			// Skip loopback and virtual interfaces
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			mac := iface.HardwareAddr.String()
			if mac != "" {
				macs = append(macs, mac)
			}
		}
		sort.Strings(macs)
		parts = append(parts, macs...)
	}

	// Read product_uuid as additional entropy
	if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		uuid := strings.TrimSpace(string(data))
		if uuid != "" {
			parts = append(parts, uuid)
		}
	}

	combined := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash)
}

// VerifyVPSBinding checks if the binary is running on the authorized VPS
func VerifyVPSBinding() bool {
	if EmbeddedFingerprint == "" {
		// No fingerprint embedded — skip check (dev mode)
		return true
	}
	current := GenerateFingerprint()
	return current == EmbeddedFingerprint
}

// VerifyPassword prompts for password and verifies against embedded hash
func VerifyPassword() bool {
	if EmbeddedPasswordHash == "" {
		// No password hash embedded — skip check (dev mode)
		return true
	}

	red := color.New(color.FgHiRed)
	white := color.New(color.FgHiWhite)
	green := color.New(color.FgHiGreen)

	fmt.Println()
	white.Print("  Enter authentication password: ")

	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		red.Println("\n  Failed to read input.")
		return false
	}
	password = strings.TrimSpace(password)

	// Hash the input password with the same salt used at build time
	inputHash := HashPassword(password)
	if inputHash != EmbeddedPasswordHash {
		fmt.Println()
		red.Println("  ✗ Authentication failed. Access denied.")
		return false
	}

	fmt.Println()
	green.Println("  ✓ Authentication successful.")
	fmt.Println()
	return true
}

// ShowRestrictionMessage displays the restriction notice
func ShowRestrictionMessage() {
	red := color.New(color.FgHiRed, color.Bold)
	yellow := color.New(color.FgHiYellow)
	white := color.New(color.FgHiWhite)

	fmt.Println()
	red.Println("  ╔═══════════════════════════════════════════════════════╗")
	red.Println("  ║            UNAUTHORIZED SYSTEM DETECTED              ║")
	red.Println("  ╠═══════════════════════════════════════════════════════╣")
	white.Println("  ║  This binary is licensed for use on a specific       ║")
	white.Println("  ║  server only. It cannot be used on this machine.     ║")
	red.Println("  ╠═══════════════════════════════════════════════════════╣")
	yellow.Println("  ║  To get your own licensed copy of this framework:    ║")
	yellow.Println("  ║                                                      ║")
	yellow.Println("  ║  Contact: Christ Link                                ║")
	yellow.Println("  ║  Telegram: @Christlink098                            ║")
	red.Println("  ╚═══════════════════════════════════════════════════════╝")
	fmt.Println()
}
