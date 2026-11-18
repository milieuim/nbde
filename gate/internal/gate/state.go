package gate

import (
	"net/netip"
	"time"
)

// Limits from docs/design.md §6.5–§6.7.
const (
	ClockSkew      = 120 * time.Second
	NonceRetention = 2 * ClockSkew
	MaxArmTTL      = 600 * time.Second
	MaxApproval    = 900 * time.Second
	GracePeriod    = 60 * time.Second
	HeartbeatLost  = 180 * time.Second
	DeniedNotify   = 10 * time.Minute
	attemptHistory = 20
)

// Release reasons, as written to the audit log and notifications.
const (
	ReasonArm      = "arm"
	ReasonApproval = "approval"
	ReasonGrace    = "grace"
	ReasonDenied   = "no budget"
	ReasonFrom     = "source not allowed"
	// ReasonOther is a refusal while another source holds the grace period:
	// the expected loser of a concurrent IPv4/IPv6 race, not worth an alert.
	ReasonOther = "released to another source"
)

type approval struct {
	expires time.Time
	from    []netip.Prefix
}

type grace struct {
	until  time.Time
	source netip.Addr
}

type heartbeat struct {
	at     time.Time
	bootID string
	seq    uint64
	lost   bool
}

// Attempt is one /rec decision, kept for status.
type Attempt struct {
	At       time.Time `json:"at"`
	Kid      string    `json:"kid"`
	Source   string    `json:"source"`
	Released bool      `json:"released"`
	Reason   string    `json:"reason"`
}

// clientState is everything a gate knows about a client at runtime. It lives
// only in memory: a restart clears every budget (fail closed).
type clientState struct {
	arm          time.Time // zero: no arm
	approval     *approval
	grace        *grace
	heartbeat    *heartbeat
	attempts     []Attempt
	lastDenyNote time.Time
}

// decide applies §6.7 steps 3–6 and consumes the budget it releases from.
func (s *clientState) decide(now time.Time, source netip.Addr) (bool, string) {
	switch {
	case !s.arm.IsZero() && now.Before(s.arm):
		s.arm = time.Time{}
		s.openGrace(now, source)
		return true, ReasonArm
	case s.approval != nil && now.Before(s.approval.expires) &&
		(len(s.approval.from) == 0 || prefixesContain(s.approval.from, source)):
		s.approval = nil
		s.openGrace(now, source)
		return true, ReasonApproval
	case s.grace != nil && now.Before(s.grace.until):
		if s.grace.source == source {
			return true, ReasonGrace
		}
		return false, ReasonOther
	}
	return false, ReasonDenied
}

func (s *clientState) openGrace(now time.Time, source netip.Addr) {
	s.grace = &grace{until: now.Add(GracePeriod), source: source}
}

func (s *clientState) record(a Attempt) {
	s.attempts = append(s.attempts, a)
	if n := len(s.attempts); n > attemptHistory {
		s.attempts = append([]Attempt(nil), s.attempts[n-attemptHistory:]...)
	}
}

// shouldNoteDenial rate-limits unlock_denied notifications.
func (s *clientState) shouldNoteDenial(now time.Time) bool {
	if !s.lastDenyNote.IsZero() && now.Sub(s.lastDenyNote) < DeniedNotify {
		return false
	}
	s.lastDenyNote = now
	return true
}

// Status is the view returned by /v1/status and ctl status.
type Status struct {
	Gate      string           `json:"gate"`
	Client    string           `json:"client"`
	Now       time.Time        `json:"now"`
	Heartbeat *HeartbeatStatus `json:"heartbeat,omitempty"`
	Arm       *time.Time       `json:"arm_expires,omitempty"`
	Approval  *ApprovalStatus  `json:"approval,omitempty"`
	Grace     *time.Time       `json:"grace_until,omitempty"`
	Attempts  []Attempt        `json:"attempts"`
	// Thumbprints is only filled for ctl, the trusted channel for pinning.
	Thumbprints []string `json:"thp,omitempty"`
}

type HeartbeatStatus struct {
	At     time.Time `json:"at"`
	BootID string    `json:"boot_id"`
	Seq    uint64    `json:"seq"`
	Lost   bool      `json:"lost"`
}

type ApprovalStatus struct {
	Expires time.Time `json:"expires"`
	From    []string  `json:"from,omitempty"`
}

func (s *clientState) status(now time.Time) Status {
	st := Status{Now: now, Attempts: append([]Attempt{}, s.attempts...)}
	if hb := s.heartbeat; hb != nil {
		st.Heartbeat = &HeartbeatStatus{At: hb.at, BootID: hb.bootID, Seq: hb.seq, Lost: hb.lost}
	}
	if !s.arm.IsZero() && now.Before(s.arm) {
		t := s.arm
		st.Arm = &t
	}
	if a := s.approval; a != nil && now.Before(a.expires) {
		as := &ApprovalStatus{Expires: a.expires}
		for _, p := range a.from {
			as.From = append(as.From, p.String())
		}
		st.Approval = as
	}
	if g := s.grace; g != nil && now.Before(g.until) {
		t := g.until
		st.Grace = &t
	}
	return st
}

// nonceCache rejects a nonce seen within NonceRetention. Any message whose
// iat passes the ClockSkew check is younger than that, so a replay is caught.
type nonceCache map[string]time.Time

func (c nonceCache) use(key string, now time.Time) bool {
	for k, seen := range c {
		if now.Sub(seen) > NonceRetention {
			delete(c, k)
		}
	}
	if _, dup := c[key]; dup {
		return false
	}
	c[key] = now
	return true
}
