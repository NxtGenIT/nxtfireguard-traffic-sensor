package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/flow"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/policy"
	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

type scoreSource interface {
	Score(netip.Addr) (int32, error)
}

type backend interface {
	SendAlert(context.Context, nfg.Alert) error
	SendRecommendation(context.Context, nfg.Recommendation) error
}

// Evaluator turns a flow into alerts and recommendations. Both ends of a
// flow are evaluated, each with the other end as related IP.
type Evaluator struct {
	policy  *policy.State
	scores  scoreSource
	backend backend
	outbox  *Outbox

	// recommended maps an IP to the decisions last recommended for it, so
	// the same recommendation is not sent for every connection.
	recommended *lru.Cache[string, string]
}

func NewEvaluator(p *policy.State, s scoreSource, b backend, o *Outbox, dedupeSize int) *Evaluator {
	c, _ := lru.New[string, string](dedupeSize) // only fails for size <= 0, which config rejects
	return &Evaluator{policy: p, scores: s, backend: b, outbox: o, recommended: c}
}

func (e *Evaluator) Evaluate(f flow.Flow) {
	p := e.policy.Load()
	if p == nil {
		return // no rules from the backend yet
	}
	if p.Whitelisted(f.Src) || p.Whitelisted(f.Dst) {
		return
	}
	e.endpoint(p, "source", f.Src, f.Dst, f.Source)
	if f.Dst != f.Src {
		e.endpoint(p, "destination", f.Dst, f.Src, f.Source)
	}
}

// Forget lets the next connection of ip be recommended again, after its
// score changed.
func (e *Evaluator) Forget(ip string) {
	// Dedupe keys are canonical (see endpoint); score-updates may carry
	// any spelling, e.g. "::ffff:1.2.3.4" or uppercase IPv6.
	if a, err := netip.ParseAddr(ip); err == nil {
		ip = a.Unmap().WithZone("").String()
	}
	e.recommended.Remove(ip)
}

// ForgetAll does Forget for every IP, after the blocklists changed.
func (e *Evaluator) ForgetAll() { e.recommended.Purge() }

func (e *Evaluator) endpoint(p *policy.Policy, role string, ip, related netip.Addr, src nfg.Source) {
	if !flow.Scorable(ip) {
		return
	}
	score, err := e.scores.Score(ip)
	if err != nil {
		zap.L().Warn("score lookup failed", zap.Stringer("ip", ip), zap.Error(err))
		return
	}
	alert, blocks := p.Decide(ip, score)
	if alert {
		a := nfg.Alert{IPType: role, IP: ip.String(), RelatedIP: related.String(), SourceType: src.Type, SourceName: src.Name}
		key := strings.Join([]string{"alert", a.IPType, a.IP, a.RelatedIP, a.SourceType, a.SourceName}, "|")
		e.outbox.Add(kindAlert, key, func(ctx context.Context) error { return e.backend.SendAlert(ctx, a) }, nil)
	}
	if len(blocks) == 0 {
		return
	}

	hash := decisionHash(blocks)
	key := ip.String()
	if prev, ok := e.recommended.Get(key); ok && prev == hash {
		return
	}
	e.recommended.Add(key, hash)
	r := nfg.Recommendation{IP: key, Decisions: blocks}
	e.outbox.Add(kindRecommendation, "recommend|"+key+"|"+hash,
		func(ctx context.Context) error {
			// The message may have waited out a rate limit or retries. Send
			// it only if it is still what the current rules and score say;
			// if not, the change cleared the dedupe entry and the next
			// connection recommends the current decision.
			if !e.stillDecided(ip, hash) {
				zap.L().Debug("recommendation outdated before delivery, dropped", zap.String("ip", key))
				return nil
			}
			return e.backend.SendRecommendation(ctx, r)
		},
		func() {
			// Not delivered: allow the next connection to try again.
			if cur, ok := e.recommended.Peek(key); ok && cur == hash {
				e.recommended.Remove(key)
			}
		})
}

// stillDecided reports whether ip would get the same block decisions now.
func (e *Evaluator) stillDecided(ip netip.Addr, hash string) bool {
	p := e.policy.Load()
	if p == nil || p.Whitelisted(ip) {
		return false
	}
	score, err := e.scores.Score(ip)
	if err != nil {
		return true // cannot tell; the decision was valid when made
	}
	_, blocks := p.Decide(ip, score)
	return len(blocks) > 0 && decisionHash(blocks) == hash
}

// decisionHash identifies a set of decisions independent of their order.
func decisionHash(blocks []nfg.Decision) string {
	slices.SortFunc(blocks, func(a, b nfg.Decision) int {
		return strings.Compare(a.Reason+a.Blocklist, b.Reason+b.Blocklist)
	})
	raw, _ := json.Marshal(blocks)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}
