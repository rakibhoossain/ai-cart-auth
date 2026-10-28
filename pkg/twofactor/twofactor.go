package twofactor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// GenerateResult contains the generated TOTP secret, URI, and single-use backup codes
type GenerateResult struct {
	Secret       string   `json:"secret"`
	URI          string   `json:"uri"`
	BackupCodes  []string `json:"backupCodes"`
	BackupHashes []string `json:"backupHashes"`
}

// GenerateSecret creates a new Base32 TOTP secret, standard otpauth URI, and 10 single-use backup recovery codes
func GenerateSecret(issuer, email string) (*GenerateResult, error) {
	rawSecret := make([]byte, 20)
	if _, err := rand.Read(rawSecret); err != nil {
		return nil, fmt.Errorf("failed generating random secret: %w", err)
	}

	b32Secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rawSecret)

	if issuer == "" {
		issuer = "AiCart"
	}

	totpURI := fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.QueryEscape(issuer),
		url.QueryEscape(email),
		b32Secret,
		url.QueryEscape(issuer),
	)

	plainCodes := make([]string, 10)
	hashedCodes := make([]string, 10)

	for i := 0; i < 10; i++ {
		codeBytes := make([]byte, 5)
		if _, err := rand.Read(codeBytes); err != nil {
			return nil, fmt.Errorf("failed generating backup code: %w", err)
		}
		// Format code as 10-char hex string (e.g., 4a8b-9c2d)
		code := hex.EncodeToString(codeBytes)
		plainCodes[i] = code

		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed hashing backup code: %w", err)
		}
		hashedCodes[i] = string(hash)
	}

	return &GenerateResult{
		Secret:       b32Secret,
		URI:          totpURI,
		BackupCodes:  plainCodes,
		BackupHashes: hashedCodes,
	}, nil
}

// VerifyTOTP validates a 6-digit TOTP code against a Base32 secret with a 60s drift window (offset -2 to +2)
func VerifyTOTP(secret string, code string, t time.Time) (bool, error) {
	cleanCode := strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	cleanCode = strings.ReplaceAll(cleanCode, "-", "")
	if len(cleanCode) != 6 {
		return false, nil
	}

	for offset := -2; offset <= 2; offset++ {
		candidateTime := t.Add(time.Duration(offset*30) * time.Second)
		expected, err := GenerateTOTP(secret, candidateTime)
		if err == nil && expected == cleanCode {
			return true, nil
		}
	}
	return false, nil
}

// GenerateTOTP calculates the standard RFC 6238 HMAC-SHA1 6-digit code for a given timestamp
func GenerateTOTP(secret string, t time.Time) (string, error) {
	// Support both padded and unpadded Base32 secrets
	cleanSecret := strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleanSecret)
	if err != nil {
		key, err = base32.StdEncoding.DecodeString(cleanSecret)
		if err != nil {
			return "", fmt.Errorf("invalid base32 secret: %w", err)
		}
	}

	counter := uint64(t.Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	binCode := (int(h[offset])&0x7f)<<24 |
		(int(h[offset+1])&0xff)<<16 |
		(int(h[offset+2])&0xff)<<8 |
		(int(h[offset+3]) & 0xff)

	otp := binCode % 1000000
	return fmt.Sprintf("%06d", otp), nil
}

// VerifyBackupCode verifies a single-use backup code against an array of bcrypt hashes.
// If valid, it returns valid=true and the remaining unused hashes array (with the consumed code removed).
func VerifyBackupCode(code string, bcryptHashes []string) (bool, []string) {
	cleanCode := strings.TrimSpace(code)
	if cleanCode == "" || len(bcryptHashes) == 0 {
		return false, bcryptHashes
	}

	for i, hash := range bcryptHashes {
		trimmedHash := strings.TrimSpace(hash)
		if trimmedHash == "" {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(trimmedHash), []byte(cleanCode)); err == nil {
			// Found matching code, remove it from the slice
			remaining := make([]string, 0, len(bcryptHashes)-1)
			remaining = append(remaining, bcryptHashes[:i]...)
			remaining = append(remaining, bcryptHashes[i+1:]...)
			return true, remaining
		}
	}

	return false, bcryptHashes
}
