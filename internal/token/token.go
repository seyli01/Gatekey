// Package token issues and verifies stateless, HMAC-signed bearer tokens.
//
// A token carries its own claims and is authenticated by an HMAC-SHA256 tag, so
// verification is one hash over roughly a hundred bytes with no storage lookup
// and no shared state. Gatekey therefore never persists the tokens it issues:
// the only state revocation needs is a Denylist of install IDs, which records
// what was taken away rather than everything that was handed out.
//
// Wire format:
//
//	gk1.<base64url(claims JSON)>.<base64url(HMAC-SHA256)>
//
// The MAC covers "gk1.<payload>", version prefix included, so the scheme can be
// revised later without a stripped or swapped prefix passing verification.
//
// Two kinds of token share this format. An access token is sent on every proxied
// request and is therefore short-lived; a refresh token is sent only to the
// issuance endpoint, is stored in the OS keychain, and is long-lived. The kind is
// part of the signed claims, so one can never be replayed as the other.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// scheme prefixes every token and is covered by the signature.
const scheme = "gk1"

// MinKeyLen is the shortest accepted signing key. Below the 256-bit output of
// HMAC-SHA256 the MAC is weaker than the primitive it is built on.
const MinKeyLen = 32

// Kind distinguishes the two token roles. It is stored in the signed claims.
type Kind string

const (
	// KindAccess travels on every proxied request and expires quickly.
	KindAccess Kind = "a"
	// KindRefresh is presented only to exchange for a new access token.
	KindRefresh Kind = "r"
)

// Verification failures. Callers map these onto HTTP responses; this package
// stays free of any transport concern.
var (
	ErrMalformed  = errors.New("token: malformed")
	ErrSignature  = errors.New("token: signature mismatch")
	ErrExpired    = errors.New("token: expired")
	ErrWrongKind  = errors.New("token: wrong token kind")
	ErrWrongRoute = errors.New("token: not valid for this route")
	ErrRevoked    = errors.New("token: install revoked")
)

// Claims is the signed payload. Field names are abbreviated because they are
// base64-encoded into a header on every single request.
type Claims struct {
	InstallID string `json:"iid"` // identifies one installation, survives token rotation
	Route     string `json:"rte"` // route prefix this token may reach, e.g. "/openai"
	Kind      Kind   `json:"knd"`
	IssuedAt  int64  `json:"iat"` // Unix seconds
	ExpiresAt int64  `json:"exp"` // Unix seconds

	// Nonce makes every issued token unique. Claims are otherwise a pure function
	// of the install, the route and the current second, so two tokens minted
	// within the same second would be byte-identical and a refresh could hand back
	// the string it was meant to replace. It carries no secret and is not checked
	// on verification; it exists so tokens can be told apart in a log, and so a
	// per-token denylist remains possible later without changing the wire format.
	Nonce string `json:"jti"`
}

// Pair is the result of enrolling one installation.
type Pair struct {
	Access           string
	AccessExpiresAt  time.Time
	Refresh          string
	RefreshExpiresAt time.Time
}

// Grant is a renewed access token.
type Grant struct {
	Access    string
	ExpiresAt time.Time
}

// Denylist holds revoked install IDs. It is immutable once built: a reload
// constructs a new one and swaps it in, so readers never take a lock.
type Denylist struct {
	ids map[string]struct{}
}

// NewDenylist builds a Denylist from the install IDs listed in the configuration.
func NewDenylist(installIDs []string) *Denylist {
	ids := make(map[string]struct{}, len(installIDs))
	for _, id := range installIDs {
		if id != "" {
			ids[id] = struct{}{}
		}
	}
	return &Denylist{ids: ids}
}

// Contains reports whether an install has been revoked. The nil Denylist is
// valid and revokes nothing, which is what an Issuer starts with.
func (d *Denylist) Contains(installID string) bool {
	if d == nil {
		return false
	}
	_, found := d.ids[installID]
	return found
}

// Issuer mints and verifies tokens for one signing key.
//
// It is safe for concurrent use. Verification allocates only the decoded payload,
// and the denylist is read through an atomic pointer so a configuration reload
// never blocks the request path.
type Issuer struct {
	key        []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	denylist   atomic.Pointer[Denylist]

	// now is swapped in tests to drive expiry deterministically.
	now func() time.Time
}

// NewIssuer returns an Issuer signing with key.
//
// accessTTL should stay short (minutes): an access token is exposed on every
// request, in proxy logs and in crash reports, so its value to an attacker is
// bounded by how soon it dies. refreshTTL may be long (weeks) because a refresh
// token only ever reaches the issuance endpoint.
func NewIssuer(key []byte, accessTTL, refreshTTL time.Duration) (*Issuer, error) {
	if len(key) < MinKeyLen {
		return nil, fmt.Errorf("token: signing key must be at least %d bytes, got %d", MinKeyLen, len(key))
	}
	if accessTTL <= 0 {
		return nil, errors.New("token: access TTL must be positive")
	}
	if refreshTTL < accessTTL {
		return nil, errors.New("token: refresh TTL must be at least the access TTL")
	}

	i := &Issuer{
		key:        append([]byte(nil), key...),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		now:        time.Now,
	}
	return i, nil
}

// GenerateKey returns a fresh random signing key, for first run and for the
// dashboard's "rotate key" action. Rotating invalidates every token at once.
func GenerateKey() ([]byte, error) {
	key := make([]byte, MinKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("token: generating signing key: %w", err)
	}
	return key, nil
}

// newNonce returns the unique component stamped into every token.
func newNonce() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("token: generating nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// SetDenylist replaces the revoked install IDs, and is called on every
// configuration reload. The swap is atomic, so in-flight requests see either the
// old list or the new one, never a partial one.
func (i *Issuer) SetDenylist(d *Denylist) {
	i.denylist.Store(d)
}

// AccessTTL reports the lifetime stamped into issued access tokens.
func (i *Issuer) AccessTTL() time.Duration { return i.accessTTL }

// RefreshTTL reports the lifetime stamped into issued refresh tokens.
func (i *Issuer) RefreshTTL() time.Duration { return i.refreshTTL }

// Issue enrols an installation on a route and returns both of its tokens, using
// the issuer's configured lifetimes.
func (i *Issuer) Issue(installID, routePrefix string) (Pair, error) {
	return i.IssueWithTTL(installID, routePrefix, i.accessTTL)
}

// IssueWithTTL enrols an installation with an explicit access-token lifetime.
//
// It exists for callers that cannot refresh: a cron job or a backend worker has
// nowhere to run a renewal loop, so it takes one long-lived token instead. That
// token is still bound to an install ID, so it stays revocable through the
// denylist and still says who is calling -- neither of which a hand-written
// constant in a configuration file ever did.
//
// The refresh token is stretched to at least the access lifetime, since a
// refresh credential that died first could renew nothing.
func (i *Issuer) IssueWithTTL(installID, routePrefix string, accessTTL time.Duration) (Pair, error) {
	if installID == "" {
		return Pair{}, errors.New("token: install ID must not be empty")
	}
	if routePrefix == "" {
		return Pair{}, errors.New("token: route prefix must not be empty")
	}
	if accessTTL <= 0 {
		return Pair{}, errors.New("token: access TTL must be positive")
	}

	refreshTTL := max(i.refreshTTL, accessTTL)

	now := i.now()
	accessExp := now.Add(accessTTL)
	refreshExp := now.Add(refreshTTL)

	access, err := i.sign(Claims{
		InstallID: installID,
		Route:     routePrefix,
		Kind:      KindAccess,
		IssuedAt:  now.Unix(),
		ExpiresAt: accessExp.Unix(),
	})
	if err != nil {
		return Pair{}, err
	}

	refresh, err := i.sign(Claims{
		InstallID: installID,
		Route:     routePrefix,
		Kind:      KindRefresh,
		IssuedAt:  now.Unix(),
		ExpiresAt: refreshExp.Unix(),
	})
	if err != nil {
		return Pair{}, err
	}

	return Pair{
		Access:           access,
		AccessExpiresAt:  accessExp,
		Refresh:          refresh,
		RefreshExpiresAt: refreshExp,
	}, nil
}

// Refresh exchanges a valid refresh token for a new access token.
//
// The refresh token is deliberately not rotated. Rotation only means something
// when the superseded token can be invalidated, and doing that statelessly is
// impossible: it would require remembering every token ever issued, which is the
// state this package exists to avoid. Returning a new refresh token while the old
// one silently stayed valid until its own expiry would look like a security
// control without being one. Revocation is the Denylist, and it cuts every token
// belonging to an install at once.
func (i *Issuer) Refresh(rawRefresh string) (Grant, error) {
	claims, err := i.Verify(rawRefresh, KindRefresh)
	if err != nil {
		return Grant{}, err
	}

	now := i.now()
	exp := now.Add(i.accessTTL)

	access, err := i.sign(Claims{
		InstallID: claims.InstallID,
		Route:     claims.Route,
		Kind:      KindAccess,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
	})
	if err != nil {
		return Grant{}, err
	}

	return Grant{Access: access, ExpiresAt: exp}, nil
}

// VerifyAccess validates an access token and binds it to the route being called,
// so a token minted for "/openai" cannot spend the budget attached to
// "/anthropic". This is the entry point for the proxy request path.
func (i *Issuer) VerifyAccess(raw, routePrefix string) (*Claims, error) {
	claims, err := i.Verify(raw, KindAccess)
	if err != nil {
		return nil, err
	}
	if claims.Route != routePrefix {
		return nil, ErrWrongRoute
	}
	return claims, nil
}

// Verify authenticates a token and returns its claims.
//
// Expiry is always evaluated against the current clock, never cached: a cached
// verdict that outlived the token would silently extend it. No skew is allowed,
// because both ends of this exchange are the same process.
func (i *Issuer) Verify(raw string, kind Kind) (*Claims, error) {
	dot := strings.LastIndexByte(raw, '.')
	if dot < 0 {
		return nil, ErrMalformed
	}
	signingInput, sigPart := raw[:dot], raw[dot+1:]
	if !strings.HasPrefix(signingInput, scheme+".") {
		return nil, ErrMalformed
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return nil, ErrMalformed
	}

	// Authenticate before decoding anything. Unmarshalling a payload whose
	// signature has not been checked would hand attacker-controlled bytes to the
	// JSON decoder, and hmac.Equal keeps the comparison constant-time.
	if !hmac.Equal(sig, i.mac(signingInput)) {
		return nil, ErrSignature
	}

	payload, err := base64.RawURLEncoding.DecodeString(signingInput[len(scheme)+1:])
	if err != nil {
		return nil, ErrMalformed
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrMalformed
	}

	// The kind is signed, so an access token presented at the refresh endpoint,
	// or a long-lived refresh token presented as a credential on the proxy path,
	// is rejected rather than honoured.
	if claims.Kind != kind {
		return nil, ErrWrongKind
	}
	if !i.now().Before(time.Unix(claims.ExpiresAt, 0)) {
		return nil, ErrExpired
	}
	if i.denylist.Load().Contains(claims.InstallID) {
		return nil, ErrRevoked
	}

	return &claims, nil
}

// sign stamps a fresh nonce, serialises the claims and appends the MAC. Minting
// happens once per refresh interval, never on the request path, so the read from
// the system entropy pool costs nothing measurable.
func (i *Issuer) sign(claims Claims) (string, error) {
	nonce, err := newNonce()
	if err != nil {
		return "", err
	}
	claims.Nonce = nonce

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("token: encoding claims: %w", err)
	}
	signingInput := scheme + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(i.mac(signingInput)), nil
}

// mac computes the authentication tag over the versioned payload.
func (i *Issuer) mac(signingInput string) []byte {
	h := hmac.New(sha256.New, i.key)
	h.Write([]byte(signingInput))
	return h.Sum(nil)
}
