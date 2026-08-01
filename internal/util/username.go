package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// For use with SSO

// GenerateUsername creates a username from email, preferred username, or fallbacks.
func GenerateUsername(email, username string, fallbacks []string) (string, error) {
	const (
		minLength = 3
		maxLength = 64
	)

	candidates := []string{username, emailToUsername(email)}
	candidates = append(candidates, fallbacks...)

	for _, candidate := range candidates {
		if sanitized := sanitize(candidate, maxLength); isValidUsername(
			sanitized,
			minLength,
			maxLength,
		) {
			return sanitized, nil
		}
	}

	// Last resort: hash the email or first available string
	source := email
	if source == "" && len(fallbacks) > 0 {
		source = fallbacks[0]
	}
	if source != "" {
		return generateHashedUsername(source, maxLength), nil
	}

	return "", fmt.Errorf("unable to generate username: no valid data provided")
}

func emailToUsername(email string) string {
	if email == "" {
		return ""
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

func sanitize(input string, maxLength int) string {
	if input == "" {
		return ""
	}

	result := strings.ToLower(input)

	result = strings.ReplaceAll(result, " ", ".")

	var cleaned strings.Builder
	for _, r := range result {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			cleaned.WriteRune(r)
		}
	}
	result = cleaned.String()

	result = regexp.MustCompile(`[._-]{2,}`).ReplaceAllString(result, ".")

	result = strings.Trim(result, "._-")

	if len(result) > maxLength {
		result = result[:maxLength]
		result = strings.TrimRight(result, "._-")
	}

	return result
}

func isValidUsername(username string, minLength, maxLength int) bool {
	if len(username) < minLength || len(username) > maxLength {
		return false
	}
	matched, _ := regexp.MatchString(`^[a-z0-9._-]+$`, username)
	return matched
}

func generateHashedUsername(input string, maxLength int) string {
	hash := sha256.Sum256([]byte(input))
	hashStr := hex.EncodeToString(hash[:])

	username := "user-" + hashStr[:12]
	if len(username) > maxLength {
		username = username[:maxLength]
	}
	return username
}
