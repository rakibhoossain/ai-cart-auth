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
	initProviders()

	http.HandleFunc("/login/", handleLogin)
	http.HandleFunc("/callback/", handleCallback)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Auth server running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
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
	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	redirectBytes, _ := base64.URLEncoding.DecodeString(state)
	redirect := string(redirectBytes)

	token, err := provider.Config.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	client := provider.Config.Client(r.Context(), token)
	resp, err := client.Get(provider.UserInfo)
	if err != nil {
		http.Error(w, "failed to fetch user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var user map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&user)

	payload := map[string]interface{}{
		"provider": providerName,
		"user":     user,
		"token":    token.AccessToken,
		"exp":      time.Now().Add(5 * time.Minute).Unix(),
	}

	jwt, _ := signJWT(payload)

	// Append payload safely; existing query params (like callbackUrl) remain intact
	final, err := appendQueryParam(redirect, "oauthPayload", jwt)
	if err != nil {
		http.Error(w, "failed to build redirect URL", http.StatusInternalServerError)
		return
	}

	// Redirect back with signed JWT payload
	http.Redirect(w, r, final, http.StatusTemporaryRedirect)
}

func signJWT(data map[string]interface{}) (string, error) {
	var jwtSecret = []byte(os.Getenv("OAUTH_SIGNING_SECRET"))
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	bodyBytes, _ := json.Marshal(data)
	body := base64.RawURLEncoding.EncodeToString(bodyBytes)

	unsigned := fmt.Sprintf("%s.%s", header, body)
	h := hmac.New(sha256.New, jwtSecret)
	h.Write([]byte(unsigned))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s", unsigned, signature), nil
}
