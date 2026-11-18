package gate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Message types for agent JWS (§6.5) and approval tokens (§6.6).
const (
	TypHeartbeat = "heartbeat"
	TypArm       = "arm"
	TypDisarm    = "disarm"
	TypApprove   = "approve"
	TypDeny      = "deny"

	jwsType      = "unlock-gate+jws"
	nonceLen     = 16
	maxBodyBytes = 8 << 10
)

// AgentClaims is the payload of a heartbeat, arm or disarm JWS.
type AgentClaims struct {
	V      int    `json:"v"`
	Typ    string `json:"typ"`
	Aud    string `json:"aud"`
	Client string `json:"client"`
	BootID string `json:"boot_id"`
	Iat    int64  `json:"iat"`
	Seq    uint64 `json:"seq,omitempty"`
	Nonce  string `json:"nonce,omitempty"`
	TTL    int64  `json:"ttl,omitempty"`
}

type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// errUnauthorized maps to 401, errConflict to 409.
var (
	errUnauthorized = errors.New("unauthorized")
	errConflict     = errors.New("conflict")
)

// SignAgent produces a compact JWS for claims. The eihort side uses it.
func SignAgent(key ed25519.PrivateKey, claims AgentClaims) (string, error) {
	header, err := json.Marshal(jwsHeader{Alg: "EdDSA", Typ: jwsType})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	return input + "." + enc.EncodeToString(ed25519.Sign(key, []byte(input))), nil
}

// parseAgentJWS verifies the signature and decodes the claims. Semantic
// checks (aud, typ, iat, nonce) are the caller's.
func parseAgentJWS(token string, key ed25519.PublicKey) (*AgentClaims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a compact JWS", errUnauthorized)
	}
	enc := base64.RawURLEncoding
	rawHeader, err1 := enc.DecodeString(parts[0])
	payload, err2 := enc.DecodeString(parts[1])
	sig, err3 := enc.DecodeString(parts[2])
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("%w: bad base64url", errUnauthorized)
	}
	var header jwsHeader
	if err := decodeStrict(rawHeader, &header); err != nil || header.Alg != "EdDSA" || header.Typ != jwsType {
		return nil, fmt.Errorf("%w: bad JWS header", errUnauthorized)
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, fmt.Errorf("%w: bad signature", errUnauthorized)
	}
	var claims AgentClaims
	if err := decodeStrict(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: bad claims: %v", errUnauthorized, err)
	}
	if claims.V != 1 {
		return nil, fmt.Errorf("%w: unsupported version %d", errUnauthorized, claims.V)
	}
	return &claims, nil
}

// checkIat rejects timestamps outside ClockSkew of now (409).
func checkIat(iat int64, now time.Time) error {
	d := now.Sub(time.Unix(iat, 0))
	if d > ClockSkew || d < -ClockSkew {
		return fmt.Errorf("%w: iat outside ±%s", errConflict, ClockSkew)
	}
	return nil
}

func checkNonce(nonce string) error {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != nonceLen {
		return fmt.Errorf("%w: nonce must be %d bytes of base64url", errUnauthorized, nonceLen)
	}
	return nil
}

// ApprovalClaims is the JSON document signed by an approver (§6.6).
type ApprovalClaims struct {
	V      int      `json:"v"`
	Typ    string   `json:"typ"`
	Client string   `json:"client"`
	Gates  []string `json:"gates"`
	Iat    int64    `json:"iat"`
	Nonce  string   `json:"nonce"`
	Window int64    `json:"window,omitempty"`
	From   []string `json:"from,omitempty"`
}

// ApprovalRequest is the body of POST /v1/approve.
type ApprovalRequest struct {
	Message   string `json:"message"`   // base64url of the signed JSON bytes
	Signature string `json:"signature"` // armored sshsig
}
