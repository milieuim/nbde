package gate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Threshold is the number of gates that must accept an arm or approval for
// it to be useful (§3.1).
const Threshold = 2

const clientTimeout = 10 * time.Second

// Endpoints maps gate id to its mesh base URL, e.g. "http://[fdcc::4]:7501".
type Endpoints map[string]string

// AgentConfig is the running client's view (eihort).
type AgentConfig struct {
	Client  string    `json:"client"`
	KeyFile string    `json:"key_file"`
	Gates   Endpoints `json:"gates"`
	ArmTTL  int64     `json:"arm_ttl"`
}

// ApproverConfig is the approver's view (the laptop).
type ApproverConfig struct {
	Client  string    `json:"client"`
	KeyFile string    `json:"key_file"`
	Gates   Endpoints `json:"gates"`
}

func loadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return decodeStrict(data, v)
}

func LoadAgentConfig(path string) (*AgentConfig, error) {
	var c AgentConfig
	if err := loadJSON(path, &c); err != nil {
		return nil, fmt.Errorf("agent config: %w", err)
	}
	if !namePattern.MatchString(c.Client) || len(c.Gates) == 0 || c.KeyFile == "" {
		return nil, errors.New("agent config needs client, key_file and gates")
	}
	if c.ArmTTL == 0 {
		c.ArmTTL = int64(MaxArmTTL / time.Second)
	}
	return &c, nil
}

func LoadApproverConfig(path string) (*ApproverConfig, error) {
	var c ApproverConfig
	if err := loadJSON(path, &c); err != nil {
		return nil, fmt.Errorf("approver config: %w", err)
	}
	if !namePattern.MatchString(c.Client) || len(c.Gates) == 0 || c.KeyFile == "" {
		return nil, errors.New("approver config needs client, key_file and gates")
	}
	return &c, nil
}

// GateIDs returns the configured gate ids, sorted.
func (e Endpoints) GateIDs() []string {
	ids := make([]string, 0, len(e))
	for id := range e {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Result is the outcome of one request to one gate.
type Result struct {
	Gate string
	Err  error
}

// fanOut runs do for every gate concurrently.
func (e Endpoints) fanOut(do func(id, base string) error) []Result {
	ids := e.GateIDs()
	results := make([]Result, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Go(func() { results[i] = Result{Gate: id, Err: do(id, e[id])} })
	}
	wg.Wait()
	return results
}

// Succeeded counts results without an error.
func Succeeded(results []Result) int {
	n := 0
	for _, r := range results {
		if r.Err == nil {
			n++
		}
	}
	return n
}

var httpClient = &http.Client{
	Timeout: clientTimeout,
	// Plain HTTP over the mesh; never follow redirects or proxies.
	Transport:     &http.Transport{Proxy: nil},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func post(url, contentType string, body []byte) error {
	resp, err := httpClient.Post(url, contentType, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// ReadAgentKey reads a base64url Ed25519 seed.
func ReadAgentKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not a base64url Ed25519 seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// CreateAgentKey writes a new seed with mode 0400 and returns the public key.
func CreateAgentKey(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return nil, err
	}
	_, werr := io.WriteString(f, base64.RawURLEncoding.EncodeToString(priv.Seed())+"\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, errors.Join(werr, os.Remove(path))
	}
	return pub, nil
}

func bootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// bootSeq increases strictly within one boot, across process restarts.
func bootSeq() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

func randomNonce() (string, error) {
	b := make([]byte, nonceLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SendAgent signs a heartbeat, arm or disarm for each gate and posts it.
func SendAgent(cfg *AgentConfig, typ string) ([]Result, error) {
	key, err := ReadAgentKey(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	boot, err := bootID()
	if err != nil {
		return nil, err
	}
	results := cfg.Gates.fanOut(func(id, base string) error {
		claims := AgentClaims{V: 1, Typ: typ, Aud: id, Client: cfg.Client, BootID: boot, Iat: time.Now().Unix()}
		var err error
		switch typ {
		case TypHeartbeat:
			claims.Seq, err = bootSeq()
		case TypArm:
			claims.TTL = cfg.ArmTTL
			claims.Nonce, err = randomNonce()
		case TypDisarm:
			claims.Nonce, err = randomNonce()
		}
		if err != nil {
			return err
		}
		token, err := SignAgent(key, claims)
		if err != nil {
			return err
		}
		return post(base+"/v1/"+typ, "application/jose", []byte(token))
	})
	return results, nil
}

// FetchStatus gets /v1/status from every gate.
func FetchStatus(gates Endpoints, client string) (map[string]Status, []Result) {
	statuses := map[string]Status{}
	var mu sync.Mutex
	results := gates.fanOut(func(id, base string) error {
		resp, err := httpClient.Get(base + "/v1/status?client=" + client)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s", resp.Status)
		}
		var st Status
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&st); err != nil {
			return err
		}
		mu.Lock()
		statuses[id] = st
		mu.Unlock()
		return nil
	})
	return statuses, results
}

// NewApproval builds the claims for an approve or deny covering every gate.
func NewApproval(cfg *ApproverConfig, typ string, window time.Duration, from []string) (ApprovalClaims, error) {
	n, err := randomNonce()
	if err != nil {
		return ApprovalClaims{}, err
	}
	c := ApprovalClaims{
		V: 1, Typ: typ, Client: cfg.Client, Gates: cfg.Gates.GateIDs(),
		Iat: time.Now().Unix(), Nonce: n, From: from,
	}
	if typ == TypApprove {
		c.Window = int64(window / time.Second)
	}
	return c, nil
}

// PostApproval sends the same signed token to every gate.
func PostApproval(gates Endpoints, message []byte, signature string) []Result {
	body, err := json.Marshal(ApprovalRequest{
		Message:   base64.RawURLEncoding.EncodeToString(message),
		Signature: signature,
	})
	if err != nil {
		return []Result{{Err: err}}
	}
	return gates.fanOut(func(_, base string) error {
		return post(base+"/v1/approve", "application/json", body)
	})
}
