package gate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/crypto/ssh"
)

const (
	home  = "198.51.100.7"
	other = "203.0.113.9"
)

type fixture struct {
	t        *testing.T
	gate     *Gate
	clock    time.Time
	agent    ed25519.PrivateKey
	approver ed25519.PrivateKey
	events   *recorder
	keysDir  string
}

type recorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *recorder) Notify(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) count(kind string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// try and try2 unwrap a result in test setup; a setup failure panics,
// which fails the test with the error and its stack.
func try[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	agentPub, agent := try2(ed25519.GenerateKey(rand.Reader))
	approverPub, approver := try2(ed25519.GenerateKey(rand.Reader))
	sshPub := try(ssh.NewPublicKey(approverPub))
	f := &fixture{
		t: t, agent: agent, approver: approver,
		events: &recorder{}, clock: time.Unix(1_800_000_000, 0),
		keysDir: t.TempDir() + "/eihort",
	}
	f.gate = f.start(string(ssh.MarshalAuthorizedKey(sshPub)), base64.RawURLEncoding.EncodeToString(agentPub))
	return f
}

func try2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

// start builds a gate over f.keysDir, as a restart would.
func (f *fixture) start(approver, agentPub string) *Gate {
	cfg := &Config{
		GateID: "sgp", PublicListen: []string{":0"}, MeshListen: []string{":0"},
		CtlSocket: "/run/x", Clients: map[string]ClientConfig{"eihort": {
			KeysDir: f.keysDir, AgentPublicKey: agentPub, Approvers: []string{approver},
		}},
	}
	if err := cfg.validate(); err != nil {
		f.t.Fatal(err)
	}
	g := try(New(cfg, f.events, slog.New(slog.NewTextHandler(io.Discard, nil))))
	g.now = func() time.Time { return f.clock }
	return g
}

func (f *fixture) advance(d time.Duration) { f.clock = f.clock.Add(d) }

func (f *fixture) kid() string {
	for kid := range f.gate.clients["eihort"].keys.exchange {
		return kid
	}
	f.t.Fatal("no exchange key")
	return ""
}

// recBody is a valid ECMR request: any point on P-521.
func recBody(t *testing.T) string {
	k := try(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
	key := try(jwk.Import(&k.PublicKey))
	if err := key.Set(jwk.AlgorithmKey, "ECMR"); err != nil {
		t.Fatal(err)
	}
	return string(try(json.Marshal(key)))
}

func (f *fixture) rec(source, kid string) int {
	return f.recWith(source, kid, recBody(f.t))
}

func (f *fixture) recWith(source, kid, body string) int {
	req := httptest.NewRequest(http.MethodPost, "/c/eihort/rec/"+kid, strings.NewReader(body))
	req.RemoteAddr = netip.AddrPortFrom(netip.MustParseAddr(source), 40000).String()
	w := httptest.NewRecorder()
	f.gate.PublicHandler().ServeHTTP(w, req)
	return w.Code
}

func (f *fixture) agentToken(c AgentClaims) string {
	if c.V == 0 {
		c.V = 1
	}
	if c.Aud == "" {
		c.Aud = "sgp"
	}
	if c.Client == "" {
		c.Client = "eihort"
	}
	if c.BootID == "" {
		c.BootID = "boot-1"
	}
	if c.Iat == 0 {
		c.Iat = f.clock.Unix()
	}
	return try(SignAgent(f.agent, c))
}

func nonce() string {
	b := make([]byte, nonceLen)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (f *fixture) arm() {
	f.t.Helper()
	if err := f.gate.AcceptAgent(TypArm, f.agentToken(AgentClaims{Typ: TypArm, Nonce: nonce(), TTL: 600})); err != nil {
		f.t.Fatal(err)
	}
}

func TestUnknownClientOrKidIs404(t *testing.T) {
	f := newFixture(t)
	if code := f.rec(home, "nope"); code != http.StatusNotFound {
		t.Fatalf("unknown kid: %d", code)
	}
	req := httptest.NewRequest(http.MethodGet, "/c/other/adv", nil)
	w := httptest.NewRecorder()
	f.gate.PublicHandler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown client: %d", w.Code)
	}
}

func TestAdvIsServedForTheClient(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/c/eihort/adv", "/c/eihort/adv/" + f.gate.clients["eihort"].keys.signing[0]} {
		w := httptest.NewRecorder()
		f.gate.PublicHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"payload"`) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
}

func TestNoBudgetIsDeniedAndNotifiedOnce(t *testing.T) {
	f := newFixture(t)
	for range 3 {
		if code := f.rec(home, f.kid()); code != http.StatusForbidden {
			t.Fatalf("got %d", code)
		}
	}
	if n := f.events.count(EventUnlockDenied); n != 1 {
		t.Fatalf("denied notified %d times", n)
	}
	f.advance(DeniedNotify + time.Second)
	f.rec(home, f.kid())
	if n := f.events.count(EventUnlockDenied); n != 2 {
		t.Fatalf("denied notified %d times after the window", n)
	}
}

func TestMalformedRequestDoesNotConsumeArm(t *testing.T) {
	f := newFixture(t)
	f.arm()
	req := httptest.NewRequest(http.MethodPost, "/c/eihort/rec/"+f.kid(), strings.NewReader(`{"kty":"EC"}`))
	req.RemoteAddr = home + ":1"
	w := httptest.NewRecorder()
	f.gate.PublicHandler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed: %d", w.Code)
	}
	if code := f.rec(home, f.kid()); code != http.StatusOK {
		t.Fatalf("arm was consumed by a malformed request: %d", code)
	}
}

func TestArmReleasesOnceThenGraceIsSameSourceOnly(t *testing.T) {
	f := newFixture(t)
	f.arm()
	if code := f.rec(home, f.kid()); code != http.StatusOK {
		t.Fatalf("armed: %d", code)
	}
	if code := f.rec(other, f.kid()); code != http.StatusForbidden {
		t.Fatalf("other source during grace: %d", code)
	}
	f.advance(30 * time.Second)
	if code := f.rec(home, f.kid()); code != http.StatusOK {
		t.Fatalf("same source during grace: %d", code)
	}
	f.advance(GracePeriod)
	if code := f.rec(home, f.kid()); code != http.StatusForbidden {
		t.Fatalf("after grace: %d", code)
	}
	if n := f.events.count(EventUnlockReleased); n != 1 {
		t.Fatalf("released notified %d times", n)
	}
}

func TestArmExpires(t *testing.T) {
	f := newFixture(t)
	f.arm()
	f.advance(MaxArmTTL + time.Second)
	if code := f.rec(home, f.kid()); code != http.StatusForbidden {
		t.Fatalf("expired arm: %d", code)
	}
}

func TestRestartClearsBudget(t *testing.T) {
	f := newFixture(t)
	f.arm()
	c := f.gate.clients["eihort"]
	restarted := f.start(f.gateApproverLine(), base64.RawURLEncoding.EncodeToString(c.agentKey))
	f.gate = restarted
	if code := f.rec(home, f.kid()); code != http.StatusForbidden {
		t.Fatalf("arm survived restart: %d", code)
	}
	if got := restarted.clients["eihort"].keys.signing; len(got) != 1 || got[0] != c.keys.signing[0] {
		t.Fatalf("keys not reused across restart: %v vs %v", got, c.keys.signing)
	}
}

func (f *fixture) gateApproverLine() string {
	return string(ssh.MarshalAuthorizedKey(f.gate.clients["eihort"].approvers[0]))
}

func TestAgentMessageChecks(t *testing.T) {
	f := newFixture(t)
	n := nonce()
	cases := []struct {
		name string
		typ  string
		tok  string
		want error
	}{
		{"wrong aud", TypArm, f.agentToken(AgentClaims{Typ: TypArm, Aud: "nrt", Nonce: nonce(), TTL: 60}), errUnauthorized},
		{"typ mismatch", TypArm, f.agentToken(AgentClaims{Typ: TypDisarm, Nonce: nonce()}), errUnauthorized},
		{"unknown client", TypArm, f.agentToken(AgentClaims{Typ: TypArm, Client: "x", Nonce: nonce(), TTL: 60}), errUnauthorized},
		{"ttl too long", TypArm, f.agentToken(AgentClaims{Typ: TypArm, Nonce: nonce(), TTL: 601}), errUnauthorized},
		{"short nonce", TypArm, f.agentToken(AgentClaims{Typ: TypArm, Nonce: "abc", TTL: 60}), errUnauthorized},
		{"old iat", TypArm, f.agentToken(AgentClaims{Typ: TypArm, Nonce: nonce(), TTL: 60, Iat: f.clock.Add(-ClockSkew - time.Second).Unix()}), errConflict},
		{"first use", TypArm, f.agentToken(AgentClaims{Typ: TypArm, Nonce: n, TTL: 60}), nil},
		{"replayed nonce", TypArm, f.agentToken(AgentClaims{Typ: TypArm, Nonce: n, TTL: 60}), errConflict},
	}
	for _, tc := range cases {
		err := f.gate.AcceptAgent(tc.typ, tc.tok)
		if (tc.want == nil) != (err == nil) || (tc.want != nil && !isErr(err, tc.want)) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}

	// A token signed by another key is refused.
	_, stranger := try2(ed25519.GenerateKey(rand.Reader))
	forged := try(SignAgent(stranger, AgentClaims{V: 1, Typ: TypArm, Aud: "sgp", Client: "eihort", BootID: "b", Iat: f.clock.Unix(), Nonce: nonce(), TTL: 60}))
	if err := f.gate.AcceptAgent(TypArm, forged); !isErr(err, errUnauthorized) {
		t.Errorf("forged: %v", err)
	}
}

func isErr(err, target error) bool {
	return err != nil && strings.Contains(err.Error(), target.Error()) // wrapped with %w
}

func TestHeartbeatSeqAndLoss(t *testing.T) {
	f := newFixture(t)
	hb := func(boot string, seq uint64) error {
		return f.gate.AcceptAgent(TypHeartbeat, f.agentToken(AgentClaims{Typ: TypHeartbeat, BootID: boot, Seq: seq}))
	}
	if err := hb("a", 1); err != nil {
		t.Fatal(err)
	}
	if err := hb("a", 1); !isErr(err, errConflict) {
		t.Fatalf("repeated seq: %v", err)
	}
	f.advance(HeartbeatLost + time.Second)
	f.gate.CheckHeartbeats()
	f.gate.CheckHeartbeats()
	if n := f.events.count(EventHeartbeatLost); n != 1 {
		t.Fatalf("lost notified %d times", n)
	}
	if err := hb("b", 1); err != nil { // new boot resets seq
		t.Fatal(err)
	}
	waitFor(t, func() bool { return f.events.count(EventHeartbeatResumed) == 1 })
	st, _ := f.gate.Status("eihort", false)
	if st.Heartbeat == nil || st.Heartbeat.BootID != "b" || st.Heartbeat.Lost {
		t.Fatalf("status: %+v", st.Heartbeat)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 100 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

// sshsigSign builds an armored sshsig the way ssh-keygen -Y sign does, with
// sign producing the inner ssh.Signature over the signed data.
func sshsigSign(t *testing.T, pub ssh.PublicKey, message []byte, sign func([]byte) *ssh.Signature) string {
	t.Helper()
	h := sha512.Sum512(message)
	data := append([]byte(sshsigMagic), ssh.Marshal(signedData{
		Namespace: SignatureNamespace, HashAlg: "sha512", Hash: h[:],
	})...)
	blob := append([]byte(sshsigMagic), ssh.Marshal(sshsigBlob{
		Version: 1, PublicKey: pub.Marshal(), Namespace: SignatureNamespace,
		HashAlg: "sha512", Signature: ssh.Marshal(sign(data)),
	})...)
	return armorBegin + "\n" + base64.StdEncoding.EncodeToString(blob) + "\n" + armorEnd + "\n"
}

func (f *fixture) approvalToken(c ApprovalClaims) ApprovalRequest {
	if c.V == 0 {
		c.V = 1
	}
	if c.Client == "" {
		c.Client = "eihort"
	}
	if c.Gates == nil {
		c.Gates = []string{"sgp", "nrt", "tyo"}
	}
	if c.Iat == 0 {
		c.Iat = f.clock.Unix()
	}
	if c.Nonce == "" {
		c.Nonce = nonce()
	}
	msg := try(json.Marshal(c))
	signer := try(ssh.NewSignerFromKey(f.approver))
	sig := sshsigSign(f.t, signer.PublicKey(), msg, func(data []byte) *ssh.Signature {
		return try(signer.Sign(rand.Reader, data))
	})
	return ApprovalRequest{Message: base64.RawURLEncoding.EncodeToString(msg), Signature: sig}
}

func TestApprovalTokenReleasesOnceFromAllowedSource(t *testing.T) {
	f := newFixture(t)
	if err := f.gate.AcceptApproval(f.approvalToken(ApprovalClaims{Typ: TypApprove, Window: 300, From: []string{"198.51.100.0/24"}})); err != nil {
		t.Fatal(err)
	}
	if code := f.rec(other, f.kid()); code != http.StatusForbidden {
		t.Fatalf("source outside from: %d", code)
	}
	if code := f.rec(home, f.kid()); code != http.StatusOK {
		t.Fatalf("approved: %d", code)
	}
	f.advance(GracePeriod + time.Second)
	if code := f.rec(home, f.kid()); code != http.StatusForbidden {
		t.Fatalf("approval reused: %d", code)
	}
}

func TestApprovalTokenChecks(t *testing.T) {
	f := newFixture(t)
	replay := f.approvalToken(ApprovalClaims{Typ: TypApprove, Window: 60})
	if err := f.gate.AcceptApproval(replay); err != nil {
		t.Fatal(err)
	}
	tampered := f.approvalToken(ApprovalClaims{Typ: TypApprove, Window: 60})
	msg, _ := base64.RawURLEncoding.DecodeString(tampered.Message)
	tampered.Message = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(msg), `"window":60`, `"window":900`, 1)))

	cases := map[string]struct {
		req  ApprovalRequest
		want error
	}{
		"replay":       {replay, errConflict},
		"tampered":     {tampered, errUnauthorized},
		"other gates":  {f.approvalToken(ApprovalClaims{Typ: TypApprove, Window: 60, Gates: []string{"nrt"}}), errUnauthorized},
		"window large": {f.approvalToken(ApprovalClaims{Typ: TypApprove, Window: 901}), errUnauthorized},
		"stale":        {f.approvalToken(ApprovalClaims{Typ: TypApprove, Window: 60, Iat: f.clock.Add(-time.Hour).Unix()}), errConflict},
		"unknown typ":  {f.approvalToken(ApprovalClaims{Typ: "arm", Window: 60}), errUnauthorized},
	}
	for name, tc := range cases {
		if err := f.gate.AcceptApproval(tc.req); !isErr(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}

	if err := f.gate.AcceptApproval(f.approvalToken(ApprovalClaims{Typ: TypDeny})); err != nil {
		t.Fatal(err)
	}
	if code := f.rec(home, f.kid()); code != http.StatusForbidden {
		t.Fatalf("after deny: %d", code)
	}
}

func TestApprovalFromStrangerKeyIsRefused(t *testing.T) {
	f := newFixture(t)
	_, f.approver = try2(ed25519.GenerateKey(rand.Reader))
	if err := f.gate.AcceptApproval(f.approvalToken(ApprovalClaims{Typ: TypApprove, Window: 60})); !isErr(err, errUnauthorized) {
		t.Fatalf("stranger: %v", err)
	}
}

// skKey is a software stand-in for an sk-ssh-ed25519 security key.
type skKey struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newSKKey(t *testing.T) skKey {
	pub, priv := try2(ed25519.GenerateKey(rand.Reader))
	wire := ssh.Marshal(struct {
		Name, Key, App string
	}{ssh.KeyAlgoSKED25519, string(pub), "ssh:"})
	return skKey{priv: priv, pub: try(ssh.ParsePublicKey(wire))}
}

// sign follows PROTOCOL.u2f: the authenticator signs
// sha256(application) || flags || counter || sha256(data).
func (k skKey) sign(data []byte, flags byte) *ssh.Signature {
	app := sha256.Sum256([]byte("ssh:"))
	msg := sha256.Sum256(data)
	signed := append(append([]byte{}, app[:]...), flags)
	signed = binary.BigEndian.AppendUint32(signed, 7)
	signed = append(signed, msg[:]...)
	rest := append([]byte{flags}, binary.BigEndian.AppendUint32(nil, 7)...)
	return &ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: ed25519.Sign(k.priv, signed), Rest: rest}
}

func TestSecurityKeySignatureNeedsUserPresence(t *testing.T) {
	k := newSKKey(t)
	msg := []byte(`{"v":1}`)
	allowed := []ssh.PublicKey{k.pub}

	touched := sshsigSign(t, k.pub, msg, func(d []byte) *ssh.Signature { return k.sign(d, 0x01) })
	if _, err := verifySSHSig(touched, msg, allowed, true); err != nil {
		t.Fatalf("touched: %v", err)
	}
	untouched := sshsigSign(t, k.pub, msg, func(d []byte) *ssh.Signature { return k.sign(d, 0x00) })
	if _, err := verifySSHSig(untouched, msg, allowed, true); err == nil {
		t.Fatal("signature without user presence accepted")
	}
	if _, err := verifySSHSig(touched, []byte(`{"v":2}`), allowed, true); err == nil {
		t.Fatal("signature over other message accepted")
	}
}

func TestRequireSecurityKeyRejectsPlainKeys(t *testing.T) {
	_, priv := try2(ed25519.GenerateKey(rand.Reader))
	signer := try(ssh.NewSignerFromKey(priv))
	msg := []byte("m")
	sig := sshsigSign(t, signer.PublicKey(), msg, func(d []byte) *ssh.Signature { return try(signer.Sign(rand.Reader, d)) })
	allowed := []ssh.PublicKey{signer.PublicKey()}
	if _, err := verifySSHSig(sig, msg, allowed, false); err != nil {
		t.Fatalf("plain key without requirement: %v", err)
	}
	if _, err := verifySSHSig(sig, msg, allowed, true); err == nil {
		t.Fatal("plain key accepted under requireSecurityKey")
	}
	cc := ClientConfig{KeysDir: "/k", AgentPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Approvers: []string{string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}}
	if err := cc.validate("eihort", true); err == nil {
		t.Fatal("config accepted a plain approver key under requireSecurityKey")
	}
}

func TestWrongNamespaceIsRefused(t *testing.T) {
	_, priv := try2(ed25519.GenerateKey(rand.Reader))
	signer := try(ssh.NewSignerFromKey(priv))
	msg := []byte("m")
	h := sha512.Sum512(msg)
	data := append([]byte(sshsigMagic), ssh.Marshal(signedData{Namespace: "git", HashAlg: "sha512", Hash: h[:]})...)
	blob := append([]byte(sshsigMagic), ssh.Marshal(sshsigBlob{
		Version: 1, PublicKey: signer.PublicKey().Marshal(), Namespace: "git", HashAlg: "sha512",
		Signature: ssh.Marshal(try(signer.Sign(rand.Reader, data))),
	})...)
	armored := armorBegin + "\n" + base64.StdEncoding.EncodeToString(blob) + "\n" + armorEnd
	if _, err := verifySSHSig(armored, msg, []ssh.PublicKey{signer.PublicKey()}, false); err == nil {
		t.Fatal("git-namespace signature accepted")
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t)
	for i := range recPerMinute {
		if code := f.rec(home, f.kid()); code == http.StatusTooManyRequests {
			t.Fatalf("limited after %d", i)
		}
	}
	if code := f.rec(home, f.kid()); code != http.StatusTooManyRequests {
		t.Fatalf("not limited: %d", code)
	}
	if code := f.rec(other, f.kid()); code == http.StatusTooManyRequests {
		t.Fatal("limit leaked to another source")
	}
	f.advance(time.Minute)
	if code := f.rec(home, f.kid()); code == http.StatusTooManyRequests {
		t.Fatal("bucket did not refill")
	}
}

func TestCtlCommands(t *testing.T) {
	f := newFixture(t)
	if _, err := f.gate.runCtl(CtlRequest{Cmd: "approve", Client: "eihort", Window: 901}); err == nil {
		t.Fatal("window over limit accepted")
	}
	if _, err := f.gate.runCtl(CtlRequest{Cmd: "approve", Client: "eihort"}); err != nil {
		t.Fatal(err)
	}
	st, err := f.gate.runCtl(CtlRequest{Cmd: "status", Client: "eihort"})
	if err != nil || st.Approval == nil || len(st.Thumbprints) == 0 {
		t.Fatalf("status: %+v %v", st, err)
	}
	if !st.Approval.Expires.Equal(f.clock.Add(DefaultWindow)) {
		t.Fatalf("default window: %v", st.Approval.Expires)
	}
	if _, err := f.gate.runCtl(CtlRequest{Cmd: "deny", Client: "eihort"}); err != nil {
		t.Fatal(err)
	}
	if code := f.rec(home, f.kid()); code != http.StatusForbidden {
		t.Fatalf("after ctl deny: %d", code)
	}
	if _, err := f.gate.runCtl(CtlRequest{Cmd: "status", Client: "nobody"}); err == nil {
		t.Fatal("unknown client accepted")
	}
}

func TestCtlSocketRoundTrip(t *testing.T) {
	f := newFixture(t)
	path := t.TempDir() + "/ctl.sock"
	ln := try(ListenCtl(path))
	defer ln.Close()
	go func() { _ = f.gate.ServeCtl(ln) }()
	resp, err := CallCtl(path, CtlRequest{Cmd: "status", Client: "eihort"})
	// Unprivileged peers are refused by closing without a reply.
	if os.Geteuid() != 0 {
		if err == nil {
			t.Fatalf("non-root peer got a reply: %+v", resp)
		}
		return
	}
	if err != nil || !resp.OK || resp.Status == nil {
		t.Fatalf("root peer: %+v %v", resp, err)
	}
}

func TestPublicStatusHasNoThumbprints(t *testing.T) {
	f := newFixture(t)
	w := httptest.NewRecorder()
	f.gate.MeshHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/status?client=eihort", nil))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"thp"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// TestRealSSHKeygenSignature checks interop with OpenSSH's own sshsig output.
func TestRealSSHKeygenSignature(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not found")
	}
	dir := t.TempDir()
	key := dir + "/id"
	msg := dir + "/msg"
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v %s", err, out)
	}
	message := []byte(`{"v":1,"typ":"approve"}`)
	if err := os.WriteFile(msg, message, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(keygen, "-Y", "sign", "-q", "-f", key, "-n", SignatureNamespace, msg).CombinedOutput(); err != nil {
		t.Fatalf("sign: %v %s", err, out)
	}
	sig := string(try(os.ReadFile(msg + ".sig")))
	pubLine := try(os.ReadFile(key + ".pub"))
	pub, _, _, _ := try4(ssh.ParseAuthorizedKey(pubLine))
	if _, err := verifySSHSig(sig, message, []ssh.PublicKey{pub}, false); err != nil {
		t.Fatalf("ssh-keygen signature rejected: %v", err)
	}
	if _, err := verifySSHSig(sig, append(message, ' '), []ssh.PublicKey{pub}, false); err == nil {
		t.Fatal("modified message accepted")
	}
}

func try4[A, B, C, D any](a A, b B, c C, d D, err error) (A, B, C, D) {
	if err != nil {
		panic(err)
	}
	return a, b, c, d
}

// TestRecAcceptsBodyWithoutAlg covers nbde-agent and tangd-style bodies,
// which carry only kty, crv, x and y.
func TestRecAcceptsBodyWithoutAlg(t *testing.T) {
	f := newFixture(t)
	f.arm()
	var members map[string]any
	if err := json.Unmarshal([]byte(recBody(t)), &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "alg")
	body := string(try(json.Marshal(members)))
	if code := f.recWith(home, f.kid(), body); code != http.StatusOK {
		t.Fatalf("body without alg: %d", code)
	}
}

func TestListenCtlRefusesALiveSocket(t *testing.T) {
	path := t.TempDir() + "/ctl.sock"
	ln := try(ListenCtl(path))
	defer ln.Close()
	if _, err := ListenCtl(path); err == nil {
		t.Fatal("replaced a live socket")
	}
	ln.SetUnlinkOnClose(false)
	_ = ln.Close()
	again := try(ListenCtl(path)) // stale now
	_ = again.Close()
}

// TestConcurrentFamiliesDoNotAlert: the agent asks a gate over IPv4 and IPv6
// at once; the loser of a successful release must not page the user.
func TestConcurrentFamiliesDoNotAlert(t *testing.T) {
	f := newFixture(t)
	f.arm()
	if code := f.rec(home, f.kid()); code != http.StatusOK {
		t.Fatalf("armed: %d", code)
	}
	if code := f.rec("2001:db8::7", f.kid()); code != http.StatusForbidden {
		t.Fatalf("other family: %d", code)
	}
	if n := f.events.count(EventUnlockDenied); n != 0 {
		t.Fatalf("alerted %d times for the losing family", n)
	}
	st, _ := f.gate.Status("eihort", false)
	if last := st.Attempts[len(st.Attempts)-1]; last.Reason != ReasonOther {
		t.Fatalf("reason: %q", last.Reason)
	}
	f.advance(GracePeriod)
	f.rec("2001:db8::7", f.kid())
	if n := f.events.count(EventUnlockDenied); n != 1 {
		t.Fatalf("a refusal after the grace period must alert, got %d", n)
	}
}

func TestApproverConfigKeyFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "approver.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	gates := `"gates":{"yidhra":"http://[fdcc::4]:7501"}`

	c, err := LoadApproverConfig(write(`{"client":"eihort","key_files":["/a","/b"],` + gates + `}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.SigningKeys(); len(got) != 2 || got[0] != "/a" || got[1] != "/b" {
		t.Fatalf("key_files order: %v", got)
	}

	c, err = LoadApproverConfig(write(`{"client":"eihort","key_file":"/a","key_files":["/b"],` + gates + `}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.SigningKeys(); len(got) != 2 || got[0] != "/a" {
		t.Fatalf("key_file first: %v", got)
	}

	if _, err := LoadApproverConfig(write(`{"client":"eihort",` + gates + `}`)); err == nil {
		t.Fatal("config without any key accepted")
	}
}
