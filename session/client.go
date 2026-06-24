package session

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/skiplist"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

const synAckTimeoutAlertThreshold = 5

type Client struct {
	die       context.Context
	dieCancel context.CancelFunc

	dialOut util.DialOutFunc

	sessionCounter atomic.Uint64

	idleSession     *skiplist.SkipList[uint64, *Session]
	idleSessionLock sync.Mutex

	sessions     map[uint64]*Session
	sessionsLock sync.Mutex

	padding *atomic.TypedValue[*padding.PaddingFactory]

	idleSessionTimeout time.Duration
	minIdleSession     int
	// maxSession is a soft upper bound on the number of concurrent
	// underlying sessions (TLS connections). When >0 and the bound is
	// reached, new streams are multiplexed onto existing sessions instead
	// of opening more connections. 0 means unlimited (original behaviour).
	maxSession int

	heartbeatInterval    time.Duration
	heartbeatQuietWindow time.Duration
	heartbeatTimeout     time.Duration

	logger logger.Logger
}

func NewClient(ctx context.Context, logger logger.Logger, dialOut util.DialOutFunc,
	_padding *atomic.TypedValue[*padding.PaddingFactory], idleSessionCheckInterval, idleSessionTimeout time.Duration, minIdleSession int, maxSession int,
	heartbeatInterval, heartbeatQuietWindow, heartbeatTimeout time.Duration,
) *Client {
	c := &Client{
		sessions:             make(map[uint64]*Session),
		dialOut:              dialOut,
		padding:              _padding,
		idleSessionTimeout:   idleSessionTimeout,
		minIdleSession:       minIdleSession,
		maxSession:           maxSession,
		heartbeatInterval:    heartbeatInterval,
		heartbeatQuietWindow: heartbeatQuietWindow,
		heartbeatTimeout:     heartbeatTimeout,
		logger:               logger,
	}
	if idleSessionCheckInterval <= time.Second*5 {
		idleSessionCheckInterval = time.Second * 30
	}
	if c.idleSessionTimeout <= time.Second*5 {
		c.idleSessionTimeout = time.Second * 30
	}
	c.die, c.dieCancel = context.WithCancel(ctx)
	c.idleSession = skiplist.NewSkipList[uint64, *Session]()
	go func() {
		for {
			time.Sleep(idleSessionCheckInterval)
			c.idleCleanup()
			select {
			case <-c.die.Done():
				return
			default:
			}
		}
	}()
	return c
}

// Reset closes all existing sessions (both idle and active) without
// cancelling the client context, so new sessions can still be created.
// This is called on network interface changes to clean up stale connections.
func (c *Client) Reset() {
	select {
	case <-c.die.Done():
		return
	default:
	}

	c.idleSessionLock.Lock()
	var idleSessions []*Session
	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		idleSessions = append(idleSessions, it.Value())
		it.MoveToNext()
	}
	c.idleSession.Clear()
	c.idleSessionLock.Unlock()

	c.sessionsLock.Lock()
	activeSessions := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		activeSessions = append(activeSessions, session)
	}
	c.sessionsLock.Unlock()

	for _, session := range idleSessions {
		activeSessions = append(activeSessions, session)
	}

	for _, session := range activeSessions {
		if session.conn != nil {
			session.conn.SetWriteDeadline(time.Now().Add(-time.Second))
		}
	}

	for _, session := range activeSessions {
		go session.Close()
	}
}

func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	select {
	case <-c.die.Done():
		return nil, io.ErrClosedPipe
	default:
	}

	if idle := c.getIdleSession(); idle != nil {
		if stream, err := c.openOn(idle); err == nil {
			return stream, nil
		}
		idle.Close()
	}

	// At/over the session cap, multiplex onto the least-loaded live session
	// instead of dialing. The cap is a SOFT target: if none is usable we
	// fall through and dial a new session rather than failing or blocking.
	if c.maxSession > 0 && c.activeSessionCount() >= c.maxSession {
		if reuse := c.leastLoadedSession(); reuse != nil {
			if stream, err := c.openOn(reuse); err == nil {
				return stream, nil
			}
		}
	}

	session, err := c.createSession(ctx)
	if session == nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	stream, err := c.openOn(session)
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to create stream: %w", err)
	}
	return stream, nil
}

// openOn opens a stream on session and keeps session.activeStreams in sync.
// The counter is bumped BEFORE OpenStream so the stream's die hook (which
// decrements it) can never fire ahead of the increment.
//
// On failure the increment must be rolled back EXACTLY ONCE. OpenStream can
// fail either before registering the stream (no die hook fired) or after, on
// a REUSED session, where the cmdSYN write failure runs Session.Close, which
// fires the stream's die hook and so already decremented the counter. To
// avoid double-counting, OpenStream hands back the stream it registered (nil
// otherwise); roll back here only when the die hook has NOT already fired,
// detected via the stream's dieErr (set on close, in the same dieOnce as the
// hook). This keeps activeStreams from underflowing below 0 on a SYN-write
// failure while leaving the success path and per-stream-close path untouched.
func (c *Client) openOn(session *Session) (net.Conn, error) {
	session.activeStreams.Add(1)
	stream, err := session.OpenStream(c.streamDieHook(session))
	if err != nil {
		if stream == nil || stream.dieErr.Load() == nil {
			session.activeStreams.Add(-1)
		}
		return nil, err
	}
	return stream, nil
}

// activeSessionCount is a soft figure used only for cap decisions; a few
// sessions above the cap may exist transiently during churn.
func (c *Client) activeSessionCount() int {
	c.sessionsLock.Lock()
	n := len(c.sessions)
	c.sessionsLock.Unlock()
	return n
}

func (c *Client) leastLoadedSession() *Session {
	c.sessionsLock.Lock()
	defer c.sessionsLock.Unlock()
	var best *Session
	var bestLoad int32
	for _, s := range c.sessions {
		if s.IsClosed() || s.connBroken.Load() {
			continue
		}
		if load := s.activeStreams.Load(); best == nil || load < bestLoad {
			best, bestLoad = s, load
		}
	}
	return best
}

func (c *Client) streamDieHook(session *Session) func() {
	return func() {
		// A session may carry several multiplexed streams when the session
		// cap is in effect. Return it to the idle pool only once its LAST
		// active stream has closed, so idleCleanup can never tear down a
		// session that still has live streams.
		if session.activeStreams.Add(-1) > 0 {
			return
		}
		// If Session is not closed, put this Stream to pool
		if !session.IsClosed() && !session.connBroken.Load() {
			select {
			case <-c.die.Done():
				// Now client has been closed
				go session.Close()
			default:
				c.idleSessionLock.Lock()
				session.idleSince = time.Now()
				c.idleSession.Insert(math.MaxUint64-session.seq, session)
				c.idleSessionLock.Unlock()
			}
		} else if session.connBroken.Load() && !session.IsClosed() {
			// The session was marked connBroken by a failed data write but
			// left open so recvLoop could keep draining in-flight responses
			// for the OTHER streams. Now that its last stream has closed there
			// is nothing left to drain, so reap it immediately rather than
			// waiting for the recvLoop read error (which can stall until the
			// TCP timeout) or the next idleCleanup pass. Such a session is
			// never inserted into the idle pool, so neither getIdleSession nor
			// idleCleanup would otherwise ever close it, and it keeps occupying
			// a max_session slot. Close is idempotent (dieOnce), matching the
			// go Close() in getIdleSession / idleCleanup.
			go session.Close()
		}
	}
}

func (c *Client) getIdleSession() (idle *Session) {
	c.idleSessionLock.Lock()
	for !c.idleSession.IsEmpty() {
		it := c.idleSession.Iterate()
		s := it.Value()
		c.idleSession.Remove(it.Key())
		if s.IsClosed() || s.connBroken.Load() {
			if s.connBroken.Load() && !s.IsClosed() {
				go s.Close()
			}
			continue
		}
		idle = s
		break
	}
	c.idleSessionLock.Unlock()
	return
}

func (c *Client) createSession(ctx context.Context) (*Session, error) {
	underlying, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	session := NewClientSession(underlying, c.padding, c.logger)
	session.client = c
	session.seq = c.sessionCounter.Add(1)
	session.dieHook = func() {
		c.idleSessionLock.Lock()
		c.idleSession.Remove(math.MaxUint64 - session.seq)
		c.idleSessionLock.Unlock()

		c.sessionsLock.Lock()
		delete(c.sessions, session.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
	c.sessions[session.seq] = session
	c.sessionsLock.Unlock()

	session.Run()
	return session, nil
}

func (c *Client) Close() error {
	c.dieCancel()

	c.sessionsLock.Lock()
	sessionToClose := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessionToClose = append(sessionToClose, session)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}

	return nil
}

func (c *Client) idleCleanup() {
	c.idleCleanupExpTime(time.Now().Add(-c.idleSessionTimeout))
}

func (c *Client) idleCleanupExpTime(expTime time.Time) {
	activeCount := 0
	var sessionToClose []*Session

	c.idleSessionLock.Lock()
	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		session := it.Value()
		key := it.Key()
		it.MoveToNext()

		if session.IsClosed() || session.connBroken.Load() {
			c.idleSession.Remove(key)
			if session.connBroken.Load() && !session.IsClosed() {
				sessionToClose = append(sessionToClose, session)
			}
			continue
		}

		if session.activeStreams.Load() > 0 {
			c.idleSession.Remove(key)
			continue
		}

		if !session.idleSince.Before(expTime) {
			activeCount++
			continue
		}

		if activeCount < c.minIdleSession {
			session.idleSince = time.Now()
			activeCount++
			continue
		}

		sessionToClose = append(sessionToClose, session)
		c.idleSession.Remove(key)
	}
	c.idleSessionLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}
}
