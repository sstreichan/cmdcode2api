package app

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
)

// requireUserAccountKeys controls whether malformed upstream keys are rejected
// on write paths. The reference only ever sees user_… keys, but until Phase 1
// confirms that prefix against the real CLI, the default stays warn-only so a
// valid credential in another shape is not locked out.
var requireUserAccountKeys = false

// accountKeyPattern matches anywhere in the value, like the reference
// (auth.slice(7).match(/user_…/)); a leading anchor would reject keys that
// arrive with decorations still attached.
var accountKeyPattern = regexp.MustCompile(`user_[A-Za-z0-9_-]+`)

// normalizeAccountKey trims decorations (quotes, Bearer prefix, URL/path) and
// extracts the user_… credential. It rejects sk-…, empty and non-matching
// values.
func normalizeAccountKey(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	value = strings.Trim(value, `"'`)
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("api_key is required")
	}
	if len(value) >= 7 && strings.EqualFold(value[:7], "bearer ") {
		value = strings.TrimSpace(value[7:])
	}
	if index := strings.LastIndex(value, "/"); index >= 0 {
		value = value[index+1:]
	}
	value = strings.TrimSpace(value)
	if match := accountKeyPattern.FindString(value); match != "" {
		return match, nil
	}
	return "", fmt.Errorf("api_key must be a Command Code key containing a user_ credential")
}

// resolveAccountKey applies normalizeAccountKey according to the strictness
// flag: strict mode rejects, warn-only keeps the raw value so existing
// installations keep working.
func resolveAccountKey(name, raw string) (string, error) {
	key, err := normalizeAccountKey(raw)
	if err == nil {
		return key, nil
	}
	if requireUserAccountKeys {
		return "", err
	}
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("api_key is required")
	}
	log.Printf("[WARN] account %q: %v (accepting anyway; strict validation enables after Phase 1)", name, err)
	return strings.TrimSpace(raw), nil
}

// normalizeClientKey normalizes a local gateway key: strips quotes, a Bearer
// prefix and any path suffix (ccgw-…/v1 -> ccgw-…).
func normalizeClientKey(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.Trim(value, `"'`)
	if len(value) >= 7 && strings.EqualFold(value[:7], "bearer ") {
		value = strings.TrimSpace(value[7:])
	}
	if index := strings.Index(value, "/"); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

// clientKeyFromHeaders extracts the presented client key from Authorization
// (Bearer only) or x-api-key.
func clientKeyFromHeaders(header http.Header) string {
	if auth := strings.TrimSpace(header.Get("Authorization")); len(auth) >= 7 && strings.EqualFold(auth[:7], "bearer ") {
		if key := normalizeClientKey(auth); key != "" {
			return key
		}
	}
	return normalizeClientKey(header.Get("x-api-key"))
}
