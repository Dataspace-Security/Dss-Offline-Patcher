// Package oidc is a minimal OpenID Connect relying party (authorization code
// flow with PKCE) for the admin console. It works with any standards-based
// IdP reachable from the isolated zone: AD FS, Entra ID, Okta, Keycloak.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Issuer        string              `json:"issuer"`
	ClientID      string              `json:"client_id"`
	ClientSecret  string              `json:"client_secret"`
	RedirectURL   string              `json:"redirect_url"`
	Scopes        []string            `json:"scopes"`
	UsernameClaim string              `json:"username_claim"`
	GroupsClaim   string              `json:"groups_claim"`
	RoleGroups    map[string][]string `json:"role_groups"` // role → IdP groups granting it
	RequireMFA    bool                `json:"require_mfa"`
	MFAAMRValues  []string            `json:"mfa_amr_values"`
	MFAACRValues  []string            `json:"mfa_acr_values"`
	CACertFile    string              `json:"ca_cert_file"` // trust anchor for an internal IdP
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

type Provider struct {
	cfg  Config
	hc   *http.Client
	disc discovery

	mu   sync.Mutex
	keys map[string]crypto.PublicKey
	Now  func() time.Time
}

var defaultAMR = []string{"mfa", "otp", "hwk", "swk", "fpt", "face", "sms", "pop", "fido"}

// New discovers the provider. hc should trust the IdP's CA.
func New(ctx context.Context, cfg Config, hc *http.Client) (*Provider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc: issuer, client_id and redirect_url are required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if len(cfg.MFAAMRValues) == 0 {
		cfg.MFAAMRValues = defaultAMR
	}
	p := &Provider{cfg: cfg, hc: hc, keys: map[string]crypto.PublicKey{}, Now: time.Now}
	if err := p.getJSON(ctx, strings.TrimRight(cfg.Issuer, "/")+"/.well-known/openid-configuration", &p.disc); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if strings.TrimRight(p.disc.Issuer, "/") != strings.TrimRight(cfg.Issuer, "/") {
		return nil, fmt.Errorf("oidc discovery: issuer mismatch %q", p.disc.Issuer)
	}
	return p, nil
}

func (p *Provider) Config() Config { return p.cfg }

func (p *Provider) getJSON(ctx context.Context, u string, v any) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

func randString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// LoginState is kept (signed) in a short-lived cookie between redirect and callback.
type LoginState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Expires  int64  `json:"e"`
}

// AuthURL starts a login and returns the IdP URL and the state to persist.
func (p *Provider) AuthURL(returnTo string) (string, LoginState) {
	ls := LoginState{State: randString(), Nonce: randString(), Verifier: randString(), Return: returnTo, Expires: p.Now().Add(10 * time.Minute).Unix()}
	ch := sha256.Sum256([]byte(ls.Verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.cfg.RedirectURL},
		"scope":                 {strings.Join(p.cfg.Scopes, " ")},
		"state":                 {ls.State},
		"nonce":                 {ls.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(ch[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(p.disc.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return p.disc.AuthorizationEndpoint + sep + q.Encode(), ls
}

// Identity is the verified result of a login.
type Identity struct {
	Subject  string
	Username string
	Email    string
	Groups   []string
	Role     string // highest role granted by RoleGroups; "" = none
	MFA      bool
}

// Exchange redeems the code and verifies the ID token.
func (p *Provider) Exchange(ctx context.Context, code string, ls LoginState) (Identity, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"client_id":     {p.cfg.ClientID},
		"code_verifier": {ls.Verifier},
	}
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", p.disc.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.hc.Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()
	var tr struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr)
	if resp.StatusCode != 200 || tr.IDToken == "" {
		return Identity{}, fmt.Errorf("token endpoint: %s %s %s", resp.Status, tr.Error, tr.Desc)
	}
	claims, err := p.Verify(ctx, tr.IDToken)
	if err != nil {
		return Identity{}, err
	}
	if n, _ := claims["nonce"].(string); n == "" || n != ls.Nonce {
		return Identity{}, errors.New("id_token nonce mismatch")
	}
	return p.identity(claims), nil
}

func (p *Provider) identity(c map[string]any) Identity {
	id := Identity{}
	id.Subject, _ = c["sub"].(string)
	id.Username, _ = c[p.cfg.UsernameClaim].(string)
	id.Email, _ = c["email"].(string)
	if id.Username == "" {
		id.Username = id.Email
	}
	if id.Username == "" {
		id.Username = id.Subject
	}
	id.Groups = stringList(c[p.cfg.GroupsClaim])
	for _, a := range stringList(c["amr"]) {
		for _, m := range p.cfg.MFAAMRValues {
			if strings.EqualFold(a, m) {
				id.MFA = true
			}
		}
	}
	if acr, _ := c["acr"].(string); acr != "" {
		for _, m := range p.cfg.MFAACRValues {
			if acr == m {
				id.MFA = true
			}
		}
	}
	rank := map[string]int{"viewer": 1, "operator": 2, "approver": 3, "admin": 4}
	gs := map[string]bool{}
	for _, g := range id.Groups {
		gs[g] = true
	}
	for role, groups := range p.cfg.RoleGroups {
		for _, g := range groups {
			if gs[g] && rank[role] > rank[id.Role] {
				id.Role = role
			}
		}
	}
	return id
}

func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := []string{}
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ---- JWT verification ----

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// Verify checks signature (RS256/ES256 via JWKS), iss, aud, exp, iat.
func (p *Provider) Verify(ctx context.Context, jwt string) (map[string]any, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, errors.New("id_token: malformed")
	}
	hb, err := b64(parts[0])
	if err != nil {
		return nil, errors.New("id_token: bad header")
	}
	var hdr struct{ Alg, Kid string }
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, errors.New("id_token: bad header")
	}
	sig, err := b64(parts[2])
	if err != nil {
		return nil, errors.New("id_token: bad signature encoding")
	}
	key, err := p.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch hdr.Alg {
	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return nil, errors.New("id_token: signature invalid")
		}
	case "ES256":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 || !ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, errors.New("id_token: signature invalid")
		}
	default:
		return nil, fmt.Errorf("id_token: unsupported alg %q", hdr.Alg)
	}
	pb, err := b64(parts[1])
	if err != nil {
		return nil, errors.New("id_token: bad payload")
	}
	var c map[string]any
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, errors.New("id_token: bad payload")
	}
	if iss, _ := c["iss"].(string); strings.TrimRight(iss, "/") != strings.TrimRight(p.cfg.Issuer, "/") {
		return nil, errors.New("id_token: issuer mismatch")
	}
	audOK := false
	for _, a := range stringList(c["aud"]) {
		if a == p.cfg.ClientID {
			audOK = true
		}
	}
	if !audOK {
		return nil, errors.New("id_token: audience mismatch")
	}
	now := p.Now().Unix()
	exp, _ := c["exp"].(float64)
	if int64(exp) < now-60 {
		return nil, errors.New("id_token: expired")
	}
	if iat, ok := c["iat"].(float64); ok && int64(iat) > now+300 {
		return nil, errors.New("id_token: issued in the future")
	}
	return c, nil
}

type jwk struct {
	Kty, Kid, Use, N, E, Crv, X, Y string
}

func (p *Provider) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	p.mu.Lock()
	k, ok := p.keys[kid]
	p.mu.Unlock()
	if ok {
		return k, nil
	}
	// Unknown kid: refresh once (key rotation at the IdP).
	var set struct{ Keys []jwk }
	if err := p.getJSON(ctx, p.disc.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, j := range set.Keys {
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		switch j.Kty {
		case "RSA":
			n, err1 := b64(j.N)
			e, err2 := b64(j.E)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[j.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if j.Crv != "P-256" {
				continue
			}
			x, err1 := b64(j.X)
			y, err2 := b64(j.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[j.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		}
	}
	p.mu.Lock()
	p.keys = keys
	p.mu.Unlock()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("id_token: unknown signing key %q", kid)
}

// EndSessionURL returns the IdP logout URL, if the provider advertises one.
func (p *Provider) EndSessionURL() string { return p.disc.EndSessionEndpoint }
