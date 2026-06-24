package anytlsx

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"

	"github.com/lurixo/anytls-x/padding"
	"github.com/lurixo/anytls-x/session"
	"github.com/lurixo/anytls-x/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type ClientConfig struct {
	Password                 string
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
	MaxSession               int
	HeartbeatInterval        time.Duration
	HeartbeatQuietWindow     time.Duration
	HeartbeatTimeout         time.Duration
	// EnableMigration controls the 0-RTT rail-switch. nil enables it (the
	// default); set a non-nil false to opt out. ORed with the ANYTLS_MIGRATION env.
	EnableMigration *bool
	DialOut         util.DialOutFunc
	Logger          logger.ContextLogger
}

type Client struct {
	passwordSha256 []byte
	dialOut        util.DialOutFunc
	sessionClient  *session.Client
	padding        atomic.TypedValue[*padding.PaddingFactory]
}

func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	pw := sha256.Sum256([]byte(config.Password))
	c := &Client{
		passwordSha256: pw[:],
		dialOut:        config.DialOut,
	}
	// Initialize the padding state of this client
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &c.padding)
	c.sessionClient = session.NewClient(ctx, config.Logger, c.createOutboundConnection, &c.padding, config.IdleSessionCheckInterval, config.IdleSessionTimeout, config.MinIdleSession, config.MaxSession, config.HeartbeatInterval, config.HeartbeatQuietWindow, config.HeartbeatTimeout)
	migEnabled := config.EnableMigration == nil || *config.EnableMigration
	c.sessionClient.SetMigrationEnabled(migEnabled || session.MigrationEnvDefault())
	return c, nil
}

func (c *Client) CreateProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.sessionClient.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) createOutboundConnection(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	b := buf.NewPacket()
	defer b.Release()

	b.Write(c.passwordSha256)
	paddingLen := c.padding.Load().SamplePaddingLen()
	binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
	if paddingLen > 0 {
		// Fill in place via b.Extend to avoid a temporary alloc + copy.
		util.FillRandom(b.Extend(paddingLen))
	}

	_, err = b.WriteTo(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (h *Client) Reset() {
	h.sessionClient.Reset()
}

func (h *Client) Close() error {
	return h.sessionClient.Close()
}
