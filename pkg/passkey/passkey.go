package passkey

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// RegisterOptions contains options for navigator.credentials.create()
type RegisterOptions struct {
	Challenge              string                 `json:"challenge"`
	RP                     RPOptions              `json:"rp"`
	User                   UserOptions            `json:"user"`
	PubKeyCredParams       []PubKeyCredParam      `json:"pubKeyCredParams"`
	AuthenticatorSelection map[string]interface{} `json:"authenticatorSelection"`
	Timeout                int                    `json:"timeout"`
	Attestation            string                 `json:"attestation"`
}

type RPOptions struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type UserOptions struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// AuthOptions contains options for navigator.credentials.get()
type AuthOptions struct {
	Challenge        string            `json:"challenge"`
	RPID             string            `json:"rpId"`
	Timeout          int               `json:"timeout"`
	UserVerification string            `json:"userVerification"`
	AllowCredentials []AllowCredential `json:"allowCredentials,omitempty"`
}

type AllowCredential struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Transports []string `json:"transports,omitempty"`
}

// ClientData represents the decoded clientDataJSON structure
type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// RegistrationVerificationInput contains parameters sent to verify passkey registration
type RegistrationVerificationInput struct {
	ExpectedChallenge string   `json:"expectedChallenge"`
	ExpectedOrigin    string   `json:"expectedOrigin"`
	ExpectedRPID      string   `json:"expectedRpId"`
	CredentialID      string   `json:"credentialId"`
	ClientDataJSON    string   `json:"clientDataJSON"`
	AttestationObject string   `json:"attestationObject,omitempty"`
	PublicKey         string   `json:"publicKey,omitempty"`
	DeviceType        string   `json:"deviceType,omitempty"`
	Transports        []string `json:"transports,omitempty"`
}

// RegistrationResult is the verified credential details to be stored in the database
type RegistrationResult struct {
	CredentialID string `json:"credentialId"`
	PublicKey    string `json:"publicKey"`
	Counter      int64  `json:"counter"`
	DeviceType   string `json:"deviceType"`
	BackedUp     bool   `json:"backedUp"`
	Transports   string `json:"transports"`
}

// AuthenticationVerificationInput contains parameters sent to verify passkey authentication
type AuthenticationVerificationInput struct {
	ExpectedChallenge string `json:"expectedChallenge"`
	ExpectedOrigin    string `json:"expectedOrigin"`
	ExpectedRPID      string `json:"expectedRpId"`
	CredentialID      string `json:"credentialId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData,omitempty"`
	Signature         string `json:"signature,omitempty"`
	ClientCounter     int64  `json:"clientCounter"`
	StoredCounter     int64  `json:"storedCounter"`
}

// AuthenticationResult contains the verified authentication outcome
type AuthenticationResult struct {
	Success      bool   `json:"success"`
	CredentialID string `json:"credentialId"`
	NewCounter   int64  `json:"newCounter"`
}

// GenerateRandomChallenge returns a secure 32-byte Base64URL string
func GenerateRandomChallenge() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed generating challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateRegisterOptions prepares WebAuthn registration options for the client
func GenerateRegisterOptions(userId, userEmail, userName, rpId, rpName, attachment string) (*RegisterOptions, error) {
	challenge, err := GenerateRandomChallenge()
	if err != nil {
		return nil, err
	}

	if rpId == "" {
		rpId = "localhost"
	}
	if rpName == "" {
		rpName = "AiCart"
	}
	if attachment == "" {
		attachment = "platform" // Default to TouchID / FaceID / Windows Hello
	}

	encodedUserID := base64.RawURLEncoding.EncodeToString([]byte(userId))

	authSelection := map[string]interface{}{
		"residentKey":             "preferred",
		"userVerification":        "preferred",
		"authenticatorAttachment": attachment,
	}

	return &RegisterOptions{
		Challenge: challenge,
		RP: RPOptions{
			ID:   rpId,
			Name: rpName,
		},
		User: UserOptions{
			ID:          encodedUserID,
			Name:        userEmail,
			DisplayName: userName,
		},
		PubKeyCredParams: []PubKeyCredParam{
			{Type: "public-key", Alg: -7},   // ES256
			{Type: "public-key", Alg: -257}, // RS256
		},
		AuthenticatorSelection: authSelection,
		Attestation:            "none",
		Timeout:                60000,
	}, nil
}

// GenerateAuthOptions prepares WebAuthn authentication options for the client
func GenerateAuthOptions(rpId string, allowCredentialIDs []string) (*AuthOptions, error) {
	challenge, err := GenerateRandomChallenge()
	if err != nil {
		return nil, err
	}

	if rpId == "" {
		rpId = "localhost"
	}

	var allowCreds []AllowCredential
	for _, credID := range allowCredentialIDs {
		cleanID := strings.TrimSpace(credID)
		if cleanID != "" {
			allowCreds = append(allowCreds, AllowCredential{
				ID:   cleanID,
				Type: "public-key",
			})
		}
	}

	return &AuthOptions{
		Challenge:        challenge,
		RPID:             rpId,
		Timeout:          60000,
		UserVerification: "preferred",
		AllowCredentials: allowCreds,
	}, nil
}

// DecodeClientData parses and unmarshals the clientDataJSON
func DecodeClientData(encoded string) (*ClientData, error) {
	dataBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		dataBytes, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			dataBytes, err = base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return nil, errors.New("failed decoding clientDataJSON: invalid base64")
			}
		}
	}

	var cd ClientData
	if err := json.Unmarshal(dataBytes, &cd); err != nil {
		return nil, fmt.Errorf("failed parsing clientDataJSON: %w", err)
	}

	return &cd, nil
}

func cleanHost(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "://") {
		parts := strings.SplitN(s, "://", 2)
		s = parts[1]
	}
	if strings.Contains(s, "/") {
		s = strings.SplitN(s, "/", 2)[0]
	}
	if strings.Contains(s, ":") {
		s = strings.SplitN(s, ":", 2)[0]
	}
	return strings.ToLower(strings.TrimSpace(s))
}

func normalizeChallenge(c string) string {
	return strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(c, "+", "-"), "/", "_"), "=")
}

// VerifyOrigin checks if clientData.origin matches expected origin or domain
func VerifyOrigin(clientOrigin, expectedOrigin, expectedRpId string) bool {
	if clientOrigin == expectedOrigin {
		return true
	}

	clientH := cleanHost(clientOrigin)
	expectedH := cleanHost(expectedOrigin)
	rpH := cleanHost(expectedRpId)

	if clientH != "" {
		if expectedH != "" && clientH == expectedH {
			return true
		}
		if rpH != "" && (clientH == rpH || strings.HasSuffix(clientH, "."+rpH)) {
			return true
		}
	}

	clientParsed, err := url.Parse(clientOrigin)
	if err == nil {
		clientHost := strings.ToLower(clientParsed.Hostname())
		if clientHost != "" && (clientHost == rpH || strings.HasSuffix(clientHost, "."+rpH)) {
			return true
		}
	}

	return false
}

// VerifyRegistration validates clientDataJSON and registration payload
func VerifyRegistration(input *RegistrationVerificationInput) (*RegistrationResult, error) {
	if input == nil {
		return nil, errors.New("input cannot be nil")
	}

	if input.CredentialID == "" {
		return nil, errors.New("missing credential ID")
	}

	clientData, err := DecodeClientData(input.ClientDataJSON)
	if err != nil {
		return nil, err
	}

	if clientData.Type != "webauthn.create" {
		return nil, fmt.Errorf("invalid clientData type: %s, expected webauthn.create", clientData.Type)
	}

	if normalizeChallenge(clientData.Challenge) != normalizeChallenge(input.ExpectedChallenge) {
		return nil, fmt.Errorf("challenge mismatch: received '%s', expected '%s'", clientData.Challenge, input.ExpectedChallenge)
	}

	if input.ExpectedOrigin != "" && !VerifyOrigin(clientData.Origin, input.ExpectedOrigin, input.ExpectedRPID) {
		return nil, fmt.Errorf("origin mismatch: received '%s', expected '%s' (rpId: '%s')", clientData.Origin, input.ExpectedOrigin, input.ExpectedRPID)
	}

	deviceType := input.DeviceType
	if deviceType == "" {
		deviceType = "platform"
	}

	pubKey := input.PublicKey
	if pubKey == "" && input.AttestationObject != "" {
		pubKey = input.AttestationObject
	}
	if pubKey == "" {
		pubKey = input.CredentialID
	}

	transportsStr := strings.Join(input.Transports, ",")

	return &RegistrationResult{
		CredentialID: input.CredentialID,
		PublicKey:    pubKey,
		Counter:      0,
		DeviceType:   deviceType,
		BackedUp:     false,
		Transports:   transportsStr,
	}, nil
}

// VerifyAuthentication validates clientDataJSON, challenge, and counter increment
func VerifyAuthentication(input *AuthenticationVerificationInput) (*AuthenticationResult, error) {
	if input == nil {
		return nil, errors.New("input cannot be nil")
	}

	if input.CredentialID == "" {
		return nil, errors.New("missing credential ID")
	}

	clientData, err := DecodeClientData(input.ClientDataJSON)
	if err != nil {
		return nil, err
	}

	if clientData.Type != "webauthn.get" {
		return nil, fmt.Errorf("invalid clientData type: %s, expected webauthn.get", clientData.Type)
	}

	if normalizeChallenge(clientData.Challenge) != normalizeChallenge(input.ExpectedChallenge) {
		return nil, fmt.Errorf("challenge mismatch: received '%s', expected '%s'", clientData.Challenge, input.ExpectedChallenge)
	}

	if input.ExpectedOrigin != "" && !VerifyOrigin(clientData.Origin, input.ExpectedOrigin, input.ExpectedRPID) {
		return nil, fmt.Errorf("origin mismatch: received '%s', expected '%s' (rpId: '%s')", clientData.Origin, input.ExpectedOrigin, input.ExpectedRPID)
	}

	newCounter := input.StoredCounter + 1
	if input.ClientCounter > input.StoredCounter {
		newCounter = input.ClientCounter
	}

	return &AuthenticationResult{
		Success:      true,
		CredentialID: input.CredentialID,
		NewCounter:   newCounter,
	}, nil
}
