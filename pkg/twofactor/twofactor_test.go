package twofactor

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateSecret(t *testing.T) {
	res, err := GenerateSecret("AiCart Store", "admin@aicart.store")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(res.Secret) < 16 {
		t.Errorf("secret length too short: %s", res.Secret)
	}

	if !strings.HasPrefix(res.URI, "otpauth://totp/AiCart+Store:admin%40aicart.store?") {
		t.Errorf("unexpected uri: %s", res.URI)
	}

	if len(res.BackupCodes) != 10 {
		t.Errorf("expected 10 backup codes, got %d", len(res.BackupCodes))
	}

	if len(res.BackupHashes) != 10 {
		t.Errorf("expected 10 backup hashes, got %d", len(res.BackupHashes))
	}
}

func TestVerifyTOTP(t *testing.T) {
	res, err := GenerateSecret("AiCart", "user@aicart.store")
	if err != nil {
		t.Fatalf("failed generating secret: %v", err)
	}

	now := time.Now()
	validCode, err := GenerateTOTP(res.Secret, now)
	if err != nil {
		t.Fatalf("failed generating totp: %v", err)
	}

	if len(validCode) != 6 {
		t.Fatalf("expected 6-digit code, got %s", validCode)
	}

	// Current time verification
	ok, err := VerifyTOTP(res.Secret, validCode, now)
	if err != nil || !ok {
		t.Errorf("expected valid TOTP verification, got ok=%v, err=%v", ok, err)
	}

	// Verify drift window (-25 seconds)
	pastTime := now.Add(25 * time.Second)
	ok, _ = VerifyTOTP(res.Secret, validCode, pastTime)
	if !ok {
		t.Errorf("expected valid verification within 30s window")
	}

	// Verify outside window (>65 seconds)
	futureTime := now.Add(70 * time.Second)
	ok, _ = VerifyTOTP(res.Secret, validCode, futureTime)
	if ok {
		t.Errorf("expected failed verification outside 30s window")
	}

	// Invalid code test
	ok, _ = VerifyTOTP(res.Secret, "000000", now)
	if ok && validCode != "000000" {
		t.Errorf("expected 000000 to be invalid")
	}
}

func TestVerifyBackupCode(t *testing.T) {
	res, err := GenerateSecret("AiCart", "user@aicart.store")
	if err != nil {
		t.Fatalf("failed generating secret: %v", err)
	}

	firstCode := res.BackupCodes[0]
	hashes := res.BackupHashes

	// First verification should succeed and remove the code
	ok, remainingHashes := VerifyBackupCode(firstCode, hashes)
	if !ok {
		t.Fatalf("expected backup code verification to succeed")
	}
	if len(remainingHashes) != 9 {
		t.Fatalf("expected 9 remaining hashes, got %d", len(remainingHashes))
	}

	// Using the same code again should fail (single use)
	okAgain, _ := VerifyBackupCode(firstCode, remainingHashes)
	if okAgain {
		t.Fatalf("expected already-used backup code to fail")
	}

	// Using an invalid code should fail
	badOk, _ := VerifyBackupCode("invalid-code", remainingHashes)
	if badOk {
		t.Fatalf("expected invalid code to fail")
	}
}
