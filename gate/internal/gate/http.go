package gate

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const recPerMinute = 30

// PublicHandler serves the Tang-compatible interface (§6.3).
func (g *Gate) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /c/{client}/adv", g.handleAdv)
	mux.HandleFunc("GET /c/{client}/adv/{thp}", g.handleAdv)
	mux.HandleFunc("POST /c/{client}/rec/{kid}", g.handleRec)
	return mux
}

// MeshHandler serves the interface for the running client and approvers (§6.4).
func (g *Gate) MeshHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/heartbeat", g.handleAgent(TypHeartbeat))
	mux.HandleFunc("POST /v1/arm", g.handleAgent(TypArm))
	mux.HandleFunc("POST /v1/disarm", g.handleAgent(TypDisarm))
	mux.HandleFunc("POST /v1/approve", g.handleApprove)
	mux.HandleFunc("GET /v1/status", g.handleStatus)
	return mux
}

// NewServer applies the §6.3 limits to a handler.
func NewServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

func (g *Gate) lookup(r *http.Request) *client {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.clients[r.PathValue("client")]
}

func (g *Gate) handleAdv(w http.ResponseWriter, r *http.Request) {
	c := g.lookup(r)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	// tang.go routes on the path; hand it the path without our prefix.
	path := "/adv"
	if thp := r.PathValue("thp"); thp != "" {
		path = "/adv/" + thp
	}
	inner := r.Clone(r.Context())
	inner.URL.Path, inner.URL.RawPath, inner.RequestURI = path, "", path
	c.adv.Handler.ServeHTTP(w, inner)
}

func sourceAddr(r *http.Request) (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	return ap.Addr().Unmap(), nil
}

func (g *Gate) handleRec(w http.ResponseWriter, r *http.Request) {
	source, err := sourceAddr(r)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	if !g.limiter.allow(source, g.now()) {
		http.Error(w, "", http.StatusTooManyRequests)
		return
	}
	c := g.lookup(r)
	kid := r.PathValue("kid")
	if c == nil || !c.keys.exchange[kid] {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "", http.StatusRequestEntityTooLarge)
		return
	}
	body, err = withECMRAlg(body)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	// Compute before deciding, so a malformed request never consumes budget.
	reply, err := c.keys.set.Recover(kid, body)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	now := g.now()
	g.mu.Lock()
	released, reason := false, ReasonFrom
	if len(c.allowFrom) == 0 || prefixesContain(c.allowFrom, source) {
		released, reason = c.state.decide(now, source)
	}
	c.state.record(Attempt{At: now, Kid: kid, Source: source.String(), Released: released, Reason: reason})
	noteDenial := !released && reason != ReasonOther && c.state.shouldNoteDenial(now)
	g.mu.Unlock()

	g.log.Info("rec", "client", c.name, "kid", kid, "source", source, "released", released, "reason", reason)
	if !released {
		if noteDenial {
			g.notify(EventUnlockDenied, c.name, "unlock request refused ("+reason+")")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"not_authorized"}`)
		return
	}
	if reason != ReasonGrace {
		g.notify(EventUnlockReleased, c.name, "released via "+reason)
	}
	w.Header().Set("Content-Type", "application/jwk+json")
	_, _ = w.Write(reply)
}

// withECMRAlg adds "alg":"ECMR" to a /rec body that lacks it. clevis sends
// it, tangd does not require it, tang.go does (docs/clevis-format.md §2.3).
func withECMRAlg(body []byte) ([]byte, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, err
	}
	if _, ok := members["alg"]; ok {
		return body, nil
	}
	members["alg"] = json.RawMessage(`"ECMR"`)
	return json.Marshal(members)
}

// httpError maps verification errors to status codes.
func httpError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, errUnauthorized):
		http.Error(w, err.Error(), http.StatusUnauthorized)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

func (g *Gate) handleAgent(typ string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(w, r)
		if err == nil {
			err = g.AcceptAgent(typ, string(body))
		}
		if err != nil {
			g.log.Warn("agent message rejected", "typ", typ, "remote", r.RemoteAddr, "err", err)
			httpError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (g *Gate) handleApprove(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(w, r)
	if err == nil {
		var req ApprovalRequest
		if err = decodeStrict(body, &req); err != nil {
			err = fmt.Errorf("%w: %v", errUnauthorized, err)
		} else {
			err = g.AcceptApproval(req)
		}
	}
	if err != nil {
		g.log.Warn("approval rejected", "remote", r.RemoteAddr, "err", err)
		httpError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Gate) handleStatus(w http.ResponseWriter, r *http.Request) {
	st, ok := g.Status(r.URL.Query().Get("client"), false)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

// AcceptAgent verifies and applies a heartbeat, arm or disarm JWS.
func (g *Gate) AcceptAgent(typ, token string) error {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()

	claims, c, err := g.verifyAgent(token, typ)
	if err != nil {
		return err
	}
	if err := checkIat(claims.Iat, now); err != nil {
		return err
	}
	switch typ {
	case TypHeartbeat:
		return g.applyHeartbeat(c, claims, now)
	case TypArm:
		if claims.TTL <= 0 || claims.TTL > int64(MaxArmTTL/time.Second) {
			return fmt.Errorf("%w: ttl must be in (0, %d]", errUnauthorized, int64(MaxArmTTL/time.Second))
		}
		if err := g.useNonce(c.name, claims.Nonce, now); err != nil {
			return err
		}
		c.state.arm = now.Add(time.Duration(claims.TTL) * time.Second)
		g.log.Info("armed", "client", c.name, "boot_id", claims.BootID, "expires", c.state.arm)
		go g.notify(EventArmReceived, c.name, fmt.Sprintf("armed for %ds", claims.TTL))
	case TypDisarm:
		if err := g.useNonce(c.name, claims.Nonce, now); err != nil {
			return err
		}
		c.state.arm = time.Time{}
		g.log.Info("disarmed", "client", c.name, "via", "agent")
	}
	return nil
}

// verifyAgent must be called with g.mu held.
func (g *Gate) verifyAgent(token, typ string) (*AgentClaims, *client, error) {
	// The key depends on the client named inside the payload, so peek at it
	// first; nothing is trusted until the signature verifies.
	name, err := peekClient(token)
	if err != nil {
		return nil, nil, err
	}
	c, ok := g.clients[name]
	if !ok {
		return nil, nil, fmt.Errorf("%w: unknown client", errUnauthorized)
	}
	claims, err := parseAgentJWS(token, c.agentKey)
	if err != nil {
		return nil, nil, err
	}
	if claims.Typ != typ || claims.Aud != g.id || claims.Client != name || claims.BootID == "" {
		return nil, nil, fmt.Errorf("%w: typ, aud, client or boot_id mismatch", errUnauthorized)
	}
	return claims, c, nil
}

func peekClient(token string) (string, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: not a compact JWS", errUnauthorized)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: bad base64url", errUnauthorized)
	}
	var peek struct {
		Client string `json:"client"`
	}
	if err := json.Unmarshal(payload, &peek); err != nil {
		return "", fmt.Errorf("%w: bad claims", errUnauthorized)
	}
	return peek.Client, nil
}

// useNonce must be called with g.mu held.
func (g *Gate) useNonce(client, nonce string, now time.Time) error {
	if err := checkNonce(nonce); err != nil {
		return err
	}
	if !g.nonces.use(client+"/"+nonce, now) {
		return fmt.Errorf("%w: nonce replayed", errConflict)
	}
	return nil
}

// applyHeartbeat must be called with g.mu held.
func (g *Gate) applyHeartbeat(c *client, claims *AgentClaims, now time.Time) error {
	hb := c.state.heartbeat
	if hb != nil && hb.bootID == claims.BootID && claims.Seq <= hb.seq {
		return fmt.Errorf("%w: seq %d not after %d", errConflict, claims.Seq, hb.seq)
	}
	if hb != nil && hb.lost {
		detail := "heartbeat resumed, boot " + claims.BootID
		if hb.bootID != claims.BootID {
			detail += " (was " + hb.bootID + ")"
		}
		go g.notify(EventHeartbeatResumed, c.name, detail)
	}
	c.state.heartbeat = &heartbeat{at: now, bootID: claims.BootID, seq: claims.Seq}
	return nil
}

// AcceptApproval verifies an approver-signed token and applies it.
func (g *Gate) AcceptApproval(req ApprovalRequest) error {
	message, err := base64.RawURLEncoding.DecodeString(req.Message)
	if err != nil {
		return fmt.Errorf("%w: message is not base64url", errUnauthorized)
	}
	var claims ApprovalClaims
	if err := decodeStrict(message, &claims); err != nil {
		return fmt.Errorf("%w: bad approval: %v", errUnauthorized, err)
	}
	g.mu.Lock()
	c, ok := g.clients[claims.Client]
	g.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: unknown client", errUnauthorized)
	}
	// Verify the exact bytes that were signed before trusting any field.
	if _, err := verifySSHSig(req.Signature, message, c.approvers, g.requireSK); err != nil {
		return fmt.Errorf("%w: %v", errUnauthorized, err)
	}
	if claims.V != 1 || !contains(claims.Gates, g.id) {
		return fmt.Errorf("%w: version or gates mismatch", errUnauthorized)
	}
	from, err := parsePrefixes(claims.From)
	if err != nil {
		return fmt.Errorf("%w: %v", errUnauthorized, err)
	}
	window := time.Duration(claims.Window) * time.Second
	switch claims.Typ {
	case TypApprove:
		if window <= 0 || window > MaxApproval {
			return fmt.Errorf("%w: window must be in (0, %s]", errUnauthorized, MaxApproval)
		}
	case TypDeny:
	default:
		return fmt.Errorf("%w: unknown typ %q", errUnauthorized, claims.Typ)
	}

	now := g.now()
	g.mu.Lock()
	err = checkIat(claims.Iat, now)
	if err == nil {
		err = g.useNonce(c.name, claims.Nonce, now)
	}
	g.mu.Unlock()
	if err != nil {
		return err
	}
	if claims.Typ == TypDeny {
		return g.Deny(c.name, "token")
	}
	return g.Approve(c.name, window, from, "token")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// rateLimiter is a per-address token bucket.
type rateLimiter struct {
	mu      sync.Mutex
	burst   float64
	per     time.Duration
	buckets map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(burst int, per time.Duration) *rateLimiter {
	return &rateLimiter{burst: float64(burst), per: per, buckets: map[netip.Addr]*bucket{}}
}

func (l *rateLimiter) allow(addr netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	rate := l.burst / float64(l.per)
	for a, b := range l.buckets {
		if now.Sub(b.last) > l.per {
			delete(l.buckets, a)
		}
	}
	b, ok := l.buckets[addr]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[addr] = b
	}
	b.tokens = min(l.burst, b.tokens+rate*float64(now.Sub(b.last)))
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Listen binds every address, closing what it opened on failure.
func Listen(addrs []string) ([]net.Listener, error) {
	lns := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range lns {
				_ = l.Close()
			}
			return nil, fmt.Errorf("listen %s: %w", addr, err)
		}
		lns = append(lns, ln)
	}
	return lns, nil
}

// Serve serves h on every listener until one fails.
func Serve(lns []net.Listener, h http.Handler) error {
	errs := make(chan error, len(lns))
	for _, ln := range lns {
		srv := NewServer(h)
		go func() { errs <- srv.Serve(ln) }()
	}
	return <-errs
}
