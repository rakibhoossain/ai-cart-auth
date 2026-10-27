package passkey

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestGenerateRegisterOptions(t *testing.T) {
	opts, err := GenerateRegisterOptions("user-uuid-123", "admin@aicart.store", "Admin User", "aicart.localhost", "AiCart Store", "platform")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if opts.Challenge == "" {
		t.Errorf("expected non-empty challenge")
	}

	if opts.RP.ID != "aicart.localhost" {
		t.Errorf("expected rpId 'aicart.localhost', got '%s'", opts.RP.ID)
	}

	if opts.RP.Name != "AiCart Store" {
		t.Errorf("expected rpName 'AiCart Store', got '%s'", opts.RP.Name)
	}

	if opts.User.Name != "admin@aicart.store" {
		t.Errorf("expected user name 'admin@aicart.store', got '%s'", opts.User.Name)
	}

	if len(opts.PubKeyCredParams) != 2 {
		t.Errorf("expected 2 algorithms, got %d", len(opts.PubKeyCredParams))
	}
}

func TestVerifyRegistration(t *testing.T) {
	challenge := "test-challenge-1234567890abcdef"
	origin := "https://dashboard.aicart.localhost"
	rpId := "aicart.localhost"

	clientData := ClientData{
		Type:      "webauthn.create",
		Challenge: challenge,
		Origin:    origin,
	}
	clientDataBytes, _ := json.Marshal(clientData)
	encodedClientData := base64.RawURLEncoding.EncodeToString(clientDataBytes)

	input := &RegistrationVerificationInput{
		ExpectedChallenge: challenge,
		ExpectedOrigin:    origin,
		ExpectedRPID:      rpId,
		CredentialID:      "cred-id-abc-xyz",
		ClientDataJSON:    encodedClientData,
		PublicKey:         "public-key-cose-bytes",
		DeviceType:        "platform",
		Transports:        []string{"internal", "hybrid"},
	}

	res, err := VerifyRegistration(input)
	if err != nil {
		t.Fatalf("expected successful registration verification, got error: %v", err)
	}

	if res.CredentialID != "cred-id-abc-xyz" {
		t.Errorf("unexpected credentialId: %s", res.CredentialID)
	}
	if res.Counter != 0 {
		t.Errorf("expected initial counter 0, got %d", res.Counter)
	}
	if res.Transports != "internal,hybrid" {
		t.Errorf("unexpected transports: %s", res.Transports)
	}

	// Test challenge mismatch
	badInput := *input
	badInput.ExpectedChallenge = "different-challenge"
	_, err = VerifyRegistration(&badInput)
	if err == nil {
		t.Errorf("expected error on challenge mismatch, got nil")
	}

	// Test invalid clientData type
	badTypeClientData := ClientData{
		Type:      "webauthn.get",
		Challenge: challenge,
		Origin:    origin,
	}
	badBytes, _ := json.Marshal(badTypeClientData)
	badInput2 := *input
	badInput2.ClientDataJSON = base64.RawURLEncoding.EncodeToString(badBytes)
	_, err = VerifyRegistration(&badInput2)
	if err == nil {
		t.Errorf("expected error on invalid type, got nil")
	}
}

func TestVerifyAuthentication(t *testing.T) {
	challenge := "auth-challenge-9876543210"
	origin := "https://aicart.localhost"
	rpId := "aicart.localhost"

	clientData := ClientData{
		Type:      "webauthn.get",
		Challenge: challenge,
		Origin:    origin,
	}
	clientDataBytes, _ := json.Marshal(clientData)
	encodedClientData := base64.RawURLEncoding.EncodeToString(clientDataBytes)

	input := &AuthenticationVerificationInput{
		ExpectedChallenge: challenge,
		ExpectedOrigin:    origin,
		ExpectedRPID:      rpId,
		CredentialID:      "cred-id-abc-xyz",
		ClientDataJSON:    encodedClientData,
		ClientCounter:     5,
		StoredCounter:     2,
	}

	res, err := VerifyAuthentication(input)
	if err != nil {
		t.Fatalf("expected successful authentication verification, got error: %v", err)
	}

	if !res.Success {
		t.Errorf("expected success to be true")
	}
	if res.NewCounter != 5 {
		t.Errorf("expected new counter 5, got %d", res.NewCounter)
	}

	// Test fallback counter increment when client counter is not higher
	input2 := *input
	input2.ClientCounter = 0
	input2.StoredCounter = 2
	res2, err := VerifyAuthentication(&input2)
	if err != nil || res2.NewCounter != 3 {
		t.Errorf("expected fallback counter 3, got %d", res2.NewCounter)
	}
}
