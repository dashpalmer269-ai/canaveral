package evidence

import (
	"fmt"
	"slices"
	"time"

	"github.com/dashpalmer269-ai/canaveral/internal/models"
)

// legalTransitions lists the states each state may move to. A node never
// steps back down (for example Verified to Observed), and a contradiction is
// only cleared through an explicit, reasoned move to Inconclusive.
var legalTransitions = map[models.EvidenceState][]models.EvidenceState{
	models.StateObserved:     {models.StateVerified, models.StateCorroborated, models.StateContradicted, models.StateInconclusive},
	models.StateVerified:     {models.StateCorroborated, models.StateContradicted, models.StateInconclusive},
	models.StateCorroborated: {models.StateContradicted, models.StateInconclusive},
	models.StateContradicted: {models.StateInconclusive},
	models.StateInconclusive: {models.StateVerified, models.StateCorroborated, models.StateContradicted},
	models.StateUnavailable:  {models.StateObserved},
}

// CanTransition reports whether from -> to is a legal state change.
// Staying in the same state is not a transition and returns false.
func CanTransition(from, to models.EvidenceState) bool {
	return slices.Contains(legalTransitions[from], to)
}

// Transition moves a node to a new state. reason is required. Moving to
// Corroborated requires evidence that, together with the node itself, spans
// at least two distinct evidence classes; this blocks same-class
// self-corroboration but does not check subject linkage, which belongs to the
// verification stage. Moving to Contradicted requires at least one evidence
// node. Requesting the node's current state is a no-op.
func (g *Graph) Transition(id NodeID, to models.EvidenceState, at time.Time, reason string, evidence ...NodeID) error {
	if reason == "" {
		return ErrReasonRequired
	}
	if at.IsZero() {
		return fmt.Errorf("%w: zero transition time", ErrInvalidObservation)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	e, ok := g.nodes[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownNode, id)
	}
	from := e.node.State
	if from == to {
		return nil
	}
	if !CanTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s for %s", ErrIllegalTransition, from, to, id)
	}
	ev, err := g.checkEvidence(id, evidence)
	if err != nil {
		return err
	}

	switch to {
	case models.StateCorroborated:
		classes := map[models.EvidenceClass]bool{}
		if c, ok := ClassOf(e.node.Kind); ok {
			classes[c] = true
		}
		for _, eid := range ev {
			if c, ok := ClassOf(g.nodes[eid].node.Kind); ok {
				classes[c] = true
			}
		}
		if len(classes) < 2 {
			return fmt.Errorf("%w: %s has %d", ErrInsufficientCorroboration, id, len(classes))
		}
	case models.StateContradicted:
		if len(ev) == 0 {
			return fmt.Errorf("%w: %s -> %s", ErrEvidenceRequired, from, to)
		}
	}

	e.node.StateHistory = append(e.node.StateHistory, StateChange{
		At: at.UTC(), From: from, To: to, Reason: reason, Evidence: ev,
	})
	e.node.State = to
	g.resize(e)
	return nil
}

// SetSeverity changes a node's severity and records why. Lowering is allowed
// (for example when a baseline contradicts a finding) but is always recorded,
// and MaxSeverity keeps the highest severity the node ever had.
func (g *Graph) SetSeverity(id NodeID, sev models.Severity, at time.Time, reason string, evidence ...NodeID) error {
	if reason == "" {
		return ErrReasonRequired
	}
	if at.IsZero() {
		return fmt.Errorf("%w: zero severity-change time", ErrInvalidObservation)
	}
	if sev > models.SeverityHigh {
		return fmt.Errorf("%w: invalid severity %d", ErrInvalidObservation, sev)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	e, ok := g.nodes[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownNode, id)
	}
	if e.node.Severity == sev {
		return nil
	}
	ev, err := g.checkEvidence(id, evidence)
	if err != nil {
		return err
	}
	e.node.SeverityHistory = append(e.node.SeverityHistory, SeverityChange{
		At: at.UTC(), From: e.node.Severity, To: sev, Reason: reason, Evidence: ev,
	})
	e.node.Severity = sev
	if sev > e.node.MaxSeverity {
		e.node.MaxSeverity = sev
	}
	g.resize(e)
	return nil
}

// checkEvidence verifies that every evidence ID exists and is not the subject
// itself, and returns them deduplicated in their given order.
func (g *Graph) checkEvidence(subject NodeID, evidence []NodeID) ([]NodeID, error) {
	var out []NodeID
	for _, eid := range evidence {
		if eid == subject {
			return nil, fmt.Errorf("%w: %s cannot be evidence for itself", ErrInvalidEdge, eid)
		}
		if _, ok := g.nodes[eid]; !ok {
			return nil, fmt.Errorf("%w: evidence %s", ErrUnknownNode, eid)
		}
		if !slices.Contains(out, eid) {
			out = append(out, eid)
		}
	}
	return out, nil
}
