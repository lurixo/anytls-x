package session

import "testing"

// TestShouldReapOnSynAckTimeout pins the app-switch regression: a SYNACK
// timeout must never tear down a session that still carries other (live)
// streams, while a sole-stream (idle-reused, silently dead) session is reaped
// at once and a wholly unresponsive link is still torn down at the threshold.
func TestShouldReapOnSynAckTimeout(t *testing.T) {
	s := &Session{}

	s.activeStreams.Store(3)
	if s.shouldReapOnSynAckTimeout(1) {
		t.Fatal("reaped a session with live sibling streams on a single SYNACK timeout")
	}
	if !s.shouldReapOnSynAckTimeout(synAckTimeoutAlertThreshold) {
		t.Fatal("did not reap after the consecutive-timeout threshold")
	}

	s.activeStreams.Store(1)
	if !s.shouldReapOnSynAckTimeout(1) {
		t.Fatal("did not reap a sole-stream dead session on the first SYNACK timeout")
	}

	s.activeStreams.Store(0)
	if !s.shouldReapOnSynAckTimeout(1) {
		t.Fatal("did not reap a zero-stream dead session")
	}
}
