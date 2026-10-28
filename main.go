package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"

	"ai-cart-auth/pkg/passkey"
	"ai-cart-auth/pkg/twofactor"
)

func init() {
	// Load .env file automatically when the app starts
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found — falling back to system environment")
	}
}

type Provider struct {
	Config   *oauth2.Config
	UserInfo string
}

var providers map[string]Provider

func main() {
	// Validate required environment variables
	if err := validateEnv(); err != nil {
		log.Fatalf("Environment validation failed: %v", err)
	}

	initProviders()

	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/login/", handleLogin)
	http.HandleFunc("/callback/", handleCallback)

	// 2FA TOTP & Backup Handlers
	http.HandleFunc("/api/v1/twofactor/generate", handleTwoFactorGenerate)
	http.HandleFunc("/api/v1/twofactor/verify-totp", handleTwoFactorVerifyTOTP)
	http.HandleFunc("/api/v1/twofactor/verify-backup", handleTwoFactorVerifyBackup)

	// Passkey FIDO2 Handlers
	http.HandleFunc("/api/v1/passkey/generate-register-options", handlePasskeyGenerateRegisterOptions)
	http.HandleFunc("/api/v1/passkey/verify-registration", handlePasskeyVerifyRegistration)
	http.HandleFunc("/api/v1/passkey/generate-auth-options", handlePasskeyGenerateAuthOptions)
	http.HandleFunc("/api/v1/passkey/verify-authentication", handlePasskeyVerifyAuthentication)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Auth server running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// validateEnv checks that required environment variables are set
func validateEnv() error {
	required := []string{"APP_URL", "OAUTH_SIGNING_SECRET"}

	for _, key := range required {
		if os.Getenv(key) == "" {
			return fmt.Errorf("required environment variable %s is not set", key)
		}
	}

	// Validate that at least one OAuth provider is configured
	hasProvider := false
	providers := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{"Google", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"},
		{"GitHub", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"},
		{"LinkedIn", "LINKEDIN_CLIENT_ID", "LINKEDIN_CLIENT_SECRET"},
		{"Facebook", "FACEBOOK_CLIENT_ID", "FACEBOOK_CLIENT_SECRET"},
	}

	for _, p := range providers {
		if os.Getenv(p.clientID) != "" && os.Getenv(p.clientSecret) != "" {
			hasProvider = true
			log.Printf("%s OAuth provider configured", p.name)
		}
	}

	if !hasProvider {
		return fmt.Errorf("no OAuth providers configured")
	}

	return nil
}

// handleHealth provides a health check endpoint
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"version": "1.0.0",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func initProviders() {

	appUrl := os.Getenv("APP_URL")
	providers = map[string]Provider{
		"google": {
			Config: &oauth2.Config{
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  fmt.Sprintf("%s/callback/google", appUrl),
				Scopes:       []string{"openid", "email", "profile"},
				Endpoint:     google.Endpoint,
			},
			UserInfo: "https://www.googleapis.com/oauth2/v2/userinfo",
		},
		"github": {
			Config: &oauth2.Config{
				ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
				ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
				RedirectURL:  fmt.Sprintf("%s/callback/github", appUrl),
				Scopes:       []string{"user:email"},
				Endpoint:     github.Endpoint,
			},
			UserInfo: "https://api.github.com/user",
		},
		"linkedin": {
			Config: &oauth2.Config{
				ClientID:     os.Getenv("LINKEDIN_CLIENT_ID"),
				ClientSecret: os.Getenv("LINKEDIN_CLIENT_SECRET"),
				RedirectURL:  fmt.Sprintf("%s/callback/linkedin", appUrl),
				Scopes:       []string{"r_emailaddress", "r_liteprofile"},
				Endpoint:     linkedin.Endpoint,
			},
			UserInfo: "https://api.linkedin.com/v2/userinfo",
		},
		"facebook": {
			Config: &oauth2.Config{
				ClientID:     os.Getenv("FACEBOOK_CLIENT_ID"),
				ClientSecret: os.Getenv("FACEBOOK_CLIENT_SECRET"),
				RedirectURL:  fmt.Sprintf("%s/callback/facebook", appUrl),
				Scopes:       []string{"email", "public_profile"},
				Endpoint:     facebook.Endpoint,
			},
			UserInfo: "https://graph.facebook.com/me?fields=id,name,email,picture",
		},
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	providerName := strings.TrimPrefix(r.URL.Path, "/login/")
	redirect := r.URL.Query().Get("redirect")

	if providerName == "" || redirect == "" {
		http.Error(w, "missing provider or redirect", http.StatusBadRequest)
		return
	}

	// Validate redirect URL
	if !isValidRedirectURL(redirect) {
		log.Printf("Invalid redirect URL: %s", redirect)
		http.Error(w, "invalid redirect URL", http.StatusBadRequest)
		return
	}

	provider, ok := providers[providerName]
	if !ok {
		http.Error(w, "unsupported provider", http.StatusBadRequest)
		return
	}

	// Encode redirect in state to maintain security
	state := base64.URLEncoding.EncodeToString([]byte(redirect))
	authCodeURL := provider.Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

// isValidRedirectURL validates that the redirect URL is safe
func isValidRedirectURL(redirectURL string) bool {
	// Parse the URL
	u, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}

	// Must have a scheme (http or https)
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Must have a host
	if u.Host == "" {
		return false
	}

	// Optional: Add whitelist validation here if needed
	// allowedHosts := strings.Split(os.Getenv("ALLOWED_REDIRECT_HOSTS"), ",")
	// if len(allowedHosts) > 0 && allowedHosts[0] != "" {
	//     for _, host := range allowedHosts {
	//         if strings.TrimSpace(host) == u.Host {
	//             return true
	//         }
	//     }
	//     return false
	// }

	return true
}

// StandardUser represents normalized user data across all OAuth providers
type StandardUser struct {
	Email      string `json:"email"`
	Name       string `json:"name"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Photo      string `json:"photo"`
	Provider   string `json:"provider,omitempty"`
	ProviderID string `json:"provider_id,omitempty"`
}

// normalizeUserData converts provider-specific user data to standard format
func normalizeUserData(provider string, rawUser map[string]interface{}) StandardUser {
	user := StandardUser{}

	switch provider {
	case "google":
		// Google returns: email, name, given_name, family_name, picture
		if email, ok := rawUser["email"].(string); ok {
			user.Email = email
		}
		if name, ok := rawUser["name"].(string); ok {
			user.Name = name
		}
		if givenName, ok := rawUser["given_name"].(string); ok {
			user.FirstName = givenName
		}
		if familyName, ok := rawUser["family_name"].(string); ok {
			user.LastName = familyName
		}
		if picture, ok := rawUser["picture"].(string); ok {
			user.Photo = picture
		}
		if id, ok := rawUser["id"].(string); ok {
			user.ProviderID = id
		}

	case "github":
		// GitHub returns: email, name, avatar_url, login, id
		if email, ok := rawUser["email"].(string); ok {
			user.Email = email
		}
		if name, ok := rawUser["name"].(string); ok {
			user.Name = name
			// GitHub doesn't provide separate first/last names, try to split
			parts := strings.Fields(name)
			if len(parts) > 0 {
				user.FirstName = parts[0]
			}
			if len(parts) > 1 {
				user.LastName = strings.Join(parts[1:], " ")
			}
		}
		if avatarURL, ok := rawUser["avatar_url"].(string); ok {
			user.Photo = avatarURL
		}
		if id, ok := rawUser["id"].(float64); ok {
			user.ProviderID = fmt.Sprintf("%.0f", id)
		}

	case "linkedin":
		// LinkedIn v2 userinfo returns: email, name, given_name, family_name, picture
		if email, ok := rawUser["email"].(string); ok {
			user.Email = email
		}
		if name, ok := rawUser["name"].(string); ok {
			user.Name = name
		}
		if givenName, ok := rawUser["given_name"].(string); ok {
			user.FirstName = givenName
		}
		if familyName, ok := rawUser["family_name"].(string); ok {
			user.LastName = familyName
		}
		if picture, ok := rawUser["picture"].(string); ok {
			user.Photo = picture
		}
		if sub, ok := rawUser["sub"].(string); ok {
			user.ProviderID = sub
		}

	case "facebook":
		// Facebook returns: email, name, id, picture.data.url
		if email, ok := rawUser["email"].(string); ok {
			user.Email = email
		}
		if name, ok := rawUser["name"].(string); ok {
			user.Name = name
			// Facebook doesn't provide separate first/last names in basic fields, try to split
			parts := strings.Fields(name)
			if len(parts) > 0 {
				user.FirstName = parts[0]
			}
			if len(parts) > 1 {
				user.LastName = strings.Join(parts[1:], " ")
			}
		}
		// Facebook picture is nested: picture.data.url
		if picture, ok := rawUser["picture"].(map[string]interface{}); ok {
			if data, ok := picture["data"].(map[string]interface{}); ok {
				if url, ok := data["url"].(string); ok {
					user.Photo = url
				}
			}
		}
		if id, ok := rawUser["id"].(string); ok {
			user.ProviderID = id
		}
	}

	user.Provider = provider
	return user
}

// appendQueryParam safely appends a key=value to a URL, preserving existing query params
func appendQueryParam(base, key, value string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set(key, value) // replaces if already exists
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// redirectWithError redirects to the redirect URL with error query parameters
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURL, errorCode, errorDescription string) {
	if redirectURL == "" {
		// Fallback to HTTP error if no redirect URL is available
		http.Error(w, errorDescription, http.StatusBadRequest)
		return
	}

	finalURL, err := appendQueryParam(redirectURL, "error", errorCode)
	if err != nil {
		log.Printf("Failed to build error redirect URL: %v", err)
		http.Error(w, "Failed to build redirect URL", http.StatusInternalServerError)
		return
	}

	finalURL, err = appendQueryParam(finalURL, "error_description", errorDescription)
	if err != nil {
		log.Printf("Failed to add error description to redirect URL: %v", err)
		http.Error(w, "Failed to build redirect URL", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, finalURL, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/callback/"), "/")
	if len(parts) < 1 {
		http.Error(w, "invalid callback path", http.StatusBadRequest)
		return
	}

	providerName := parts[0]
	provider, ok := providers[providerName]
	if !ok {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Decode redirect URL from state first, so we can use it for error redirects
	redirectBytes, _ := base64.URLEncoding.DecodeString(state)
	redirect := string(redirectBytes)

	// Check for OAuth errors from provider
	if errorParam := r.URL.Query().Get("error"); errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		if errorDesc == "" {
			errorDesc = "OAuth provider returned an error"
		}
		log.Printf("OAuth error from provider %s: %s - %s", providerName, errorParam, errorDesc)
		redirectWithError(w, r, redirect, errorParam, errorDesc)
		return
	}

	if code == "" || state == "" {
		log.Printf("Missing code or state in callback for provider %s", providerName)
		redirectWithError(w, r, redirect, "invalid_request", "Missing authorization code or state parameter")
		return
	}

	token, err := provider.Config.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("Token exchange failed for provider %s: %v", providerName, err)
		redirectWithError(w, r, redirect, "token_exchange_failed", "Failed to exchange authorization code for token")
		return
	}

	client := provider.Config.Client(r.Context(), token)
	resp, err := client.Get(provider.UserInfo)
	if err != nil {
		log.Printf("Failed to fetch user info for provider %s: %v", providerName, err)
		redirectWithError(w, r, redirect, "user_info_failed", "Failed to fetch user information")
		return
	}
	defer resp.Body.Close()

	var rawUser map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&rawUser)

	// Normalize user data to standard format
	user := normalizeUserData(providerName, rawUser)

	payload := map[string]interface{}{
		"provider": providerName,
		"user":     user,
		"token":    token.AccessToken,
		"exp":      time.Now().Add(1 * time.Minute).Unix(),
	}

	jwt, err := signJWT(payload)
	if err != nil {
		log.Printf("Failed to sign JWT for provider %s: %v", providerName, err)
		redirectWithError(w, r, redirect, "jwt_signing_failed", "Failed to create authentication token")
		return
	}

	// Append payload safely; existing query params (like callbackUrl) remain intact
	final, err := appendQueryParam(redirect, "oauthPayload", jwt)
	if err != nil {
		log.Printf("Failed to build redirect URL: %v", err)
		redirectWithError(w, r, redirect, "redirect_failed", "Failed to build redirect URL")
		return
	}

	// Redirect back with signed JWT payload
	http.Redirect(w, r, final, http.StatusTemporaryRedirect)
}

func signJWT(data map[string]interface{}) (string, error) {
	jwtSecret := []byte(os.Getenv("OAUTH_SIGNING_SECRET"))

	// Validate secret exists and has minimum length
	if len(jwtSecret) < 32 {
		return "", fmt.Errorf("OAUTH_SIGNING_SECRET must be at least 32 characters long")
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	bodyBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT payload: %w", err)
	}

	body := base64.RawURLEncoding.EncodeToString(bodyBytes)

	unsigned := fmt.Sprintf("%s.%s", header, body)
	h := hmac.New(sha256.New, jwtSecret)
	h.Write([]byte(unsigned))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s", unsigned, signature), nil
}

// -----------------------------------------------------------------------------
// 2FA TOTP & Backup Handlers (Stateless)
// -----------------------------------------------------------------------------

func handleTwoFactorGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Issuer string `json:"issuer"`
		Email  string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	res, err := twofactor.GenerateSecret(req.Issuer, req.Email)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    res,
	})
}

func handleTwoFactorVerifyTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.Secret == "" || req.Code == "" {
		jsonError(w, http.StatusBadRequest, "Missing secret or code")
		return
	}

	valid, err := twofactor.VerifyTOTP(req.Secret, req.Code, time.Now())
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]bool{
			"valid": valid,
		},
	})
}

func handleTwoFactorVerifyBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Code         string   `json:"code"`
		BackupHashes []string `json:"backupHashes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	valid, remaining := twofactor.VerifyBackupCode(req.Code, req.BackupHashes)

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"valid":           valid,
			"remainingHashes": remaining,
		},
	})
}

// -----------------------------------------------------------------------------
// Passkey FIDO2 Handlers (Stateless)
// -----------------------------------------------------------------------------

func handlePasskeyGenerateRegisterOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		UserID     string `json:"userId"`
		UserEmail  string `json:"userEmail"`
		UserName   string `json:"userName"`
		RPID       string `json:"rpId"`
		RPName     string `json:"rpName"`
		Attachment string `json:"attachment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	opts, err := passkey.GenerateRegisterOptions(req.UserID, req.UserEmail, req.UserName, req.RPID, req.RPName, req.Attachment)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    opts,
	})
}

func handlePasskeyVerifyRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var input passkey.RegistrationVerificationInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	res, err := passkey.VerifyRegistration(&input)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    res,
	})
}

func handlePasskeyGenerateAuthOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		RPID               string   `json:"rpId"`
		AllowCredentialIDs []string `json:"allowCredentialIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	opts, err := passkey.GenerateAuthOptions(req.RPID, req.AllowCredentialIDs)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    opts,
	})
}

func handlePasskeyVerifyAuthentication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var input passkey.AuthenticationVerificationInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	res, err := passkey.VerifyAuthentication(&input)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    res,
	})
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
