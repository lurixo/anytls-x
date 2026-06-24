package anytlsx

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"

	"github.com/lurixo/anytls-x/padding"
	"github.com/lurixo/anytls-x/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Service struct {
	users           atomic.TypedValue[map[[32]byte]string]
	padding         atomic.TypedValue[*padding.PaddingFactory]
	handler         N.TCPConnectionHandlerEx
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger
	// migReg matches inbound rail-switch carriers (carrier B) back to the
	// server stream awaiting them. Non-nil only when migration is enabled.
	migReg *session.MigRegistry
	// migMinBulk is the per-service bulk-gate override handed to each server
	// session (0 = use the built-in default).
	migMinBulk int
	// migTLSOnly restricts migration to TLS flows (opaque flows stay on the mux).
	migTLSOnly bool
}

type ServiceConfig struct {
	PaddingScheme   []byte
	Users           []User
	Handler         N.TCPConnectionHandlerEx
	FallbackHandler N.TCPConnectionHandlerEx
	Logger          logger.ContextLogger
	// EnableMigration controls inbound 0-RTT rail-switch handling. nil enables it
	// (the default); set a non-nil false to opt out. ORed with ANYTLS_MIGRATION.
	EnableMigration *bool
	// MigrationMinBulkBytes overrides the post-handshake bulk gate that decides
	// when a flow is migrated (0 = built-in default 65536; clamped to a sane floor).
	MigrationMinBulkBytes int
	// MigrationTLSOnly restricts migration to TLS flows; opaque flows (UoT-UDP,
	// plaintext …) then stay on the mux. nil enables the restriction (the
	// default); set a non-nil false to also migrate opaque flows.
	MigrationTLSOnly *bool
}

type User struct {
	Name     string
	Password string
}

func NewService(config ServiceConfig) (*Service, error) {
	service := &Service{
		handler:         config.Handler,
		fallbackHandler: config.FallbackHandler,
		logger:          config.Logger,
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}

	service.users.Store(buildUserMap(config.Users))

	if !padding.UpdatePaddingScheme(config.PaddingScheme, &service.padding) {
		return nil, errors.New("incorrect padding scheme format")
	}

	if config.EnableMigration == nil || *config.EnableMigration || session.MigrationEnvDefault() {
		service.migReg = session.NewMigRegistry()
		service.migMinBulk = config.MigrationMinBulkBytes
		service.migTLSOnly = config.MigrationTLSOnly == nil || *config.MigrationTLSOnly
	}

	return service, nil
}

func buildUserMap(users []User) map[[32]byte]string {
	u := make(map[[32]byte]string, len(users))
	for _, user := range users {
		u[sha256.Sum256([]byte(user.Password))] = user.Name
	}
	return u
}

// UpdateUsers atomically swaps the whole user table. The table is treated
// as immutable copy-on-write: NewConnection only ever Loads and reads the
// map (never mutates it), so a hot update can never race the auth-path
// lookup and the map is always internally consistent.
func (s *Service) UpdateUsers(users []User) {
	s.users.Store(buildUserMap(users))
}

// NewConnection `conn` should be plaintext
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(conn)
	if err != nil {
		return err
	}
	conn = bufio.NewCachedConn(conn, b)

	by, err := b.ReadBytes(32)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, err, onClose)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], by)
	if user, ok := s.users.Load()[passwordSha256]; ok {
		ctx = auth.ContextWithUser(ctx, user)
	} else {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.New("unknown user password"), onClose)
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.Extend(err, "read padding length"), onClose)
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			return s.fallback(ctx, conn, source, E.Extend(err, "read padding"), onClose)
		}
	}

	// Rail-switch: an authenticated inbound whose first frame is a
	// cmdMigrateCarrier is a dedicated carrier B for an already-running
	// stream, not a new session. MaybeAcceptCarrier consumes it (handled) or
	// rewinds the frame header and returns conn for normal session handling.
	if s.migReg != nil {
		var handled bool
		conn, handled, err = session.MaybeAcceptCarrier(conn, s.migReg)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
	}

	serverSession := session.NewServerSession(conn, func(stream *session.Stream) {
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			s.logger.ErrorContext(ctx, "ReadAddrPort:", err)
			return
		}
		// The destination header is now consumed; the rail-switch detector must
		// observe only the inner payload from here on.
		stream.BeginMigrationPayload()

		s.handler.NewConnectionEx(ctx, stream, source, destination, onClose)
	}, &s.padding, s.logger)
	serverSession.SetMigRegistry(s.migReg)
	serverSession.SetMigMinBulk(s.migMinBulk)
	serverSession.SetMigTLSOnly(s.migTLSOnly)
	serverSession.Run()
	serverSession.Close()
	return nil
}

func (s *Service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}
