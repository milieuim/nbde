package gate

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	tang "github.com/anatol/tang.go"
	"golang.org/x/crypto/ssh"
)

// Notification events (§6.9).
const (
	EventHeartbeatLost    = "heartbeat_lost"
	EventHeartbeatResumed = "heartbeat_resumed"
	EventUnlockDenied     = "unlock_denied"
	EventUnlockReleased   = "unlock_released"
	EventArmReceived      = "arm_received"
	EventApproval         = "approval_received"
)

// Event is a notification. It carries no source address or secret: the
// user reads details through status over the mesh or ctl.
type Event struct {
	Kind   string
	Gate   string
	Client string
	Detail string
}

// Notifier delivers events; it MUST NOT block.
type Notifier interface {
	Notify(Event)
}

type client struct {
	name      string
	keys      *tangKeys
	adv       *tang.Server // serves this client's adv via tang.go
	agentKey  ed25519.PublicKey
	approvers []ssh.PublicKey
	allowFrom []netip.Prefix
	state     clientState
}

// Gate holds the configuration and all runtime state of one unlock-gate.
type Gate struct {
	id        string
	requireSK bool
	log       *slog.Logger
	notifier  Notifier
	now       func() time.Time

	mu      sync.Mutex
	clients map[string]*client
	nonces  nonceCache
	limiter *rateLimiter
}

// New loads (or creates) every client's Tang keys.
func New(cfg *Config, notifier Notifier, log *slog.Logger) (*Gate, error) {
	g := &Gate{
		id:        cfg.GateID,
		requireSK: cfg.RequireSecurityKey,
		log:       log,
		notifier:  notifier,
		now:       time.Now,
		clients:   map[string]*client{},
		nonces:    nonceCache{},
		limiter:   newRateLimiter(recPerMinute, time.Minute),
	}
	for name, cc := range cfg.Clients {
		keys, err := loadOrCreateKeys(cc.KeysDir)
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", name, err)
		}
		agentKey, err := cc.agentKey()
		if err != nil {
			return nil, err
		}
		approvers, err := cc.approverKeys()
		if err != nil {
			return nil, err
		}
		allowFrom, err := cc.allowFrom()
		if err != nil {
			return nil, err
		}
		adv := tang.NewServer()
		adv.Keys = keys.set
		g.clients[name] = &client{
			name: name, keys: keys, adv: adv, agentKey: agentKey,
			approvers: approvers, allowFrom: allowFrom,
		}
		log.Info("client loaded", "client", name, "thp", keys.signing)
	}
	return g, nil
}

func (g *Gate) notify(kind, client, detail string) {
	if g.notifier != nil {
		g.notifier.Notify(Event{Kind: kind, Gate: g.id, Client: client, Detail: detail})
	}
}

// Status returns a client's state; withThp adds the signing thumbprints.
func (g *Gate) Status(name string, withThp bool) (Status, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.clients[name]
	if !ok {
		return Status{}, false
	}
	st := c.state.status(g.now())
	st.Gate, st.Client = g.id, name
	if withThp {
		st.Thumbprints = append([]string(nil), c.keys.signing...)
	}
	return st, true
}

// Approve creates an approval (ctl path or verified token).
func (g *Gate) Approve(name string, window time.Duration, from []netip.Prefix, via string) error {
	if window <= 0 || window > MaxApproval {
		return fmt.Errorf("window must be in (0, %s]", MaxApproval)
	}
	g.mu.Lock()
	c, ok := g.clients[name]
	if ok {
		c.state.approval = &approval{expires: g.now().Add(window), from: from}
	}
	g.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown client %q", name)
	}
	g.log.Info("approval created", "client", name, "window", window, "from", from, "via", via)
	g.notify(EventApproval, name, fmt.Sprintf("approved for %s via %s", window, via))
	return nil
}

// Deny clears the approval and grace period.
func (g *Gate) Deny(name, via string) error {
	g.mu.Lock()
	c, ok := g.clients[name]
	if ok {
		c.state.approval, c.state.grace = nil, nil
	}
	g.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown client %q", name)
	}
	g.log.Info("approval denied", "client", name, "via", via)
	g.notify(EventApproval, name, "denied via "+via)
	return nil
}

// Disarm clears the arm.
func (g *Gate) Disarm(name, via string) error {
	g.mu.Lock()
	c, ok := g.clients[name]
	if ok {
		c.state.arm = time.Time{}
	}
	g.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown client %q", name)
	}
	g.log.Info("disarmed", "client", name, "via", via)
	return nil
}

// CheckHeartbeats notifies once per client when heartbeats stop.
func (g *Gate) CheckHeartbeats() {
	now := g.now()
	var lost []string
	g.mu.Lock()
	for name, c := range g.clients {
		hb := c.state.heartbeat
		if hb != nil && !hb.lost && now.Sub(hb.at) > HeartbeatLost {
			hb.lost = true
			lost = append(lost, name)
		}
	}
	g.mu.Unlock()
	for _, name := range lost {
		g.log.Warn("heartbeat lost", "client", name)
		g.notify(EventHeartbeatLost, name, fmt.Sprintf("no heartbeat for %s", HeartbeatLost))
	}
}

// RunHeartbeatMonitor calls CheckHeartbeats until stop is closed.
func (g *Gate) RunHeartbeatMonitor(stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			g.CheckHeartbeats()
		}
	}
}
