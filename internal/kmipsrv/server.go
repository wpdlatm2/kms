// Package kmipsrv serves the KMIP protocol (binary TTLV over mutual TLS) on top of the kms core.
// It accepts KMIP 1.0-1.4, 2.0, 2.1 and 3.0 requests: the attribute encoding follows the version of
// each request (1.x Attribute name/value, 2.x typed Attributes).
package kmipsrv

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wpdlatm2/localhsm/kmip"
	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
)

const maxMessage = 1 << 20

// maxBatch bounds the operations of one request message.
const maxBatch = 64

// MessageTimeout is how long the rest of a message may take once its header arrived (a client that stalls
// half-way is cut off); IdleTimeout is how long a quiet connection is kept.
var (
	MessageTimeout = 30 * time.Second
	IdleTimeout    = 5 * time.Minute
)

// supportedVersions are the protocol versions the server answers, newest first.
var supportedVersions = kmip.Supported

type Server struct {
	Svc *kms.Service
	TLS *tls.Config // must require and verify client certificates
	Log *log.Logger
	// Access is the client log: one entry per KMIP operation (the administration API has its own log).
	Access *logs.Log

	mu sync.Mutex
	ln net.Listener
	wg sync.WaitGroup
}

// ListenAndServe serves until Close is called.
func (s *Server) ListenAndServe(addr string) error {
	if s.TLS == nil || s.TLS.ClientAuth != tls.RequireAndVerifyClientCert {
		return errors.New("kmipsrv: TLS with required client certificates is mandatory")
	}
	ln, err := tls.Listen("tcp", addr, s.TLS)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve accepts connections on ln (already a TLS listener).
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	sem := make(chan struct{}, 256)
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		sem <- struct{}{}
		s.wg.Add(1)
		go func() {
			defer func() { <-sem; s.wg.Done() }()
			s.conn(c)
		}()
	}
}

// Addr returns the listening address (after Serve started).
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

func (s *Server) Close() {
	s.mu.Lock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) logf(format string, a ...any) {
	if s.Log != nil {
		s.Log.Printf(format, a...)
	}
}

func (s *Server) conn(c net.Conn) {
	defer c.Close()
	defer func() {
		if r := recover(); r != nil { // one misbehaving connection must not stop the key server
			s.logf("kmip: recovered from a panic while serving %s: %v", c.RemoteAddr(), r)
		}
	}()
	tc, ok := c.(*tls.Conn)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		s.logf("kmip: handshake from %s failed: %v", c.RemoteAddr(), err)
		if s.Access != nil { // failed authentication attempts are audit evidence
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			s.Access.Add(logs.Entry{Plane: "client", Kind: "event", Who: "unknown", Op: "tls-handshake", Result: "denied: " + shortHandshake(err), Remote: host, Category: "authentication"})
		}
		return
	}
	st := tc.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return
	}
	p := kms.ClientPrincipal(st.PeerCertificates[0].Subject.CommonName)
	remote := c.RemoteAddr().String()
	for {
		_ = c.SetReadDeadline(time.Now().Add(IdleTimeout))
		raw, err := readMessage(c, func() { _ = c.SetReadDeadline(time.Now().Add(MessageTimeout)) })
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logf("kmip: %s: %v", p.Name, err)
			}
			return
		}
		_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := c.Write(s.handle(p, remote, raw)); err != nil {
			return
		}
	}
}

// readMessage reads one TTLV message. onHeader runs once the 8-byte header arrived: the rest must follow
// promptly (a client that stalls half-way, a "slow loris", cannot hold the connection for the idle time).
func readMessage(r io.Reader, onHeader func()) ([]byte, error) {
	var h [8]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	if onHeader != nil {
		onHeader()
	}
	if h[3] != byte(kmip.TypeStructure) {
		return nil, errors.New("request is not a TTLV structure")
	}
	n := binary.BigEndian.Uint32(h[4:])
	if n > maxMessage {
		return nil, fmt.Errorf("request of %d bytes exceeds the limit", n)
	}
	buf := make([]byte, 8+int(n))
	copy(buf, h[:])
	if _, err := io.ReadFull(r, buf[8:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// failMessage builds a response for a request that could not even be parsed.
func failMessage(v kmip.Version, reason uint32, msg string) []byte {
	b, _ := respond(v, []*kmip.Item{failItem(0, "", reason, msg)}).Encode()
	return b
}

func failItem(op uint32, batchID string, reason uint32, msg string) *kmip.Item {
	bi := kmip.Struct(kmip.TagBatchItem)
	if op != 0 {
		bi.Children = append(bi.Children, kmip.Enum(kmip.TagOperation, op))
	}
	if batchID != "" {
		bi.Children = append(bi.Children, kmip.Bytes(kmip.TagUniqueBatchItemID, []byte(batchID)))
	}
	bi.Children = append(bi.Children, kmip.Enum(kmip.TagResultStatus, kmip.StatusOperationFailed),
		kmip.Enum(kmip.TagResultReason, reason), kmip.Text(kmip.TagResultMessage, msg))
	return bi
}

func respond(v kmip.Version, items []*kmip.Item) *kmip.Item {
	hdr := kmip.Struct(kmip.TagResponseHeader,
		kmip.Struct(kmip.TagProtocolVersion, kmip.Int(kmip.TagProtocolVersionMajor, i32(v.Major)), kmip.Int(kmip.TagProtocolVersionMinor, i32(v.Minor))),
		kmip.DateTime(kmip.TagTimeStamp, time.Now()),
		kmip.Int(kmip.TagBatchCount, i32(len(items))))
	return kmip.Struct(kmip.TagResponseMessage, append([]*kmip.Item{hdr}, items...)...)
}

func (s *Server) handle(p kms.Principal, remote string, raw []byte) []byte {
	req, _, err := kmip.Decode(raw)
	if err != nil || req.Tag != kmip.TagRequestMessage {
		return failMessage(kmip.Version{Major: 1, Minor: 0}, kmip.ReasonInvalidMessage, "malformed request")
	}
	hdr := req.Child(kmip.TagRequestHeader)
	if hdr == nil {
		return failMessage(kmip.Version{Major: 1, Minor: 0}, kmip.ReasonInvalidMessage, "missing request header")
	}
	pv := hdr.Child(kmip.TagProtocolVersion)
	if pv == nil || pv.Child(kmip.TagProtocolVersionMajor) == nil || pv.Child(kmip.TagProtocolVersionMinor) == nil {
		return failMessage(kmip.Version{Major: 1, Minor: 0}, kmip.ReasonInvalidMessage, "missing protocol version")
	}
	ver := kmip.Version{Major: int(pv.Child(kmip.TagProtocolVersionMajor).Num), Minor: int(pv.Child(kmip.TagProtocolVersionMinor).Num)}
	known := false
	for _, sv := range supportedVersions {
		known = known || sv == ver
	}
	var items []*kmip.Item
	batch := req.All(kmip.TagBatchItem)
	if len(batch) > maxBatch {
		return failMessage(ver, kmip.ReasonInvalidMessage, fmt.Sprintf("a request may carry at most %d operations", maxBatch))
	}
	for _, bi := range batch {
		opItem := bi.Child(kmip.TagOperation)
		if opItem == nil {
			items = append(items, failItem(0, "", kmip.ReasonInvalidMessage, "batch item without operation"))
			continue
		}
		op := opItem.Uint()
		id := ""
		if b := bi.Child(kmip.TagUniqueBatchItemID); b != nil {
			id = string(b.Bytes)
		}
		// Discover Versions is the one operation a client may send before it knows our versions.
		if !known && op != kmip.OpDiscoverVersions {
			items = append(items, failItem(op, id, kmip.ReasonInvalidMessage, fmt.Sprintf("protocol version %s is not supported", ver)))
			continue
		}
		pl := bi.Child(kmip.TagRequestPayload)
		if pl == nil {
			pl = kmip.Struct(kmip.TagRequestPayload)
		}
		out, herr := s.dispatch(p, ver, op, pl)
		s.record(p, remote, op, pl, herr)
		if herr != nil {
			items = append(items, failItem(op, id, herr.reason, herr.msg))
			continue
		}
		ok := kmip.Struct(kmip.TagBatchItem, kmip.Enum(kmip.TagOperation, op))
		if id != "" {
			ok.Children = append(ok.Children, kmip.Bytes(kmip.TagUniqueBatchItemID, []byte(id)))
		}
		ok.Children = append(ok.Children, kmip.Enum(kmip.TagResultStatus, kmip.StatusSuccess))
		if out != nil {
			ok.Children = append(ok.Children, out)
		}
		items = append(items, ok)
	}
	if len(items) == 0 {
		items = append(items, failItem(0, "", kmip.ReasonInvalidMessage, "request has no batch items"))
	}
	rv := ver
	if !known {
		rv = kmip.Version{Major: 1, Minor: 0}
		if ver.Major >= 2 {
			rv = kmip.Version{Major: 2, Minor: 0}
		}
	}
	b, err := respond(rv, items).Encode()
	if err != nil {
		return failMessage(rv, kmip.ReasonGeneralFailure, "encoding error")
	}
	return b
}

// record writes the client-log entry of one operation.
func (s *Server) record(p kms.Principal, remote string, op uint32, pl *kmip.Item, herr *opError) {
	if s.Access == nil {
		return
	}
	e := logs.Entry{Plane: "client", Kind: "request", Who: p.Name, Op: "KMIP " + kmip.OperationName(op), Result: "ok", Remote: remote}
	if u := pl.Child(kmip.TagUniqueIdentifier); u != nil {
		e.Target = u.Str()
	}
	if herr != nil {
		e.Result = "error: " + herr.msg
	}
	s.Access.Add(e)
}

type opError struct {
	reason uint32
	msg    string
}

func fromErr(err error) *opError {
	var ke *kms.Error
	if errors.As(err, &ke) {
		switch ke.Code {
		case kms.ErrNotFound:
			return &opError{kmip.ReasonItemNotFound, ke.Msg}
		case kms.ErrDenied:
			return &opError{kmip.ReasonPermissionDenied, ke.Msg}
		case kms.ErrState:
			return &opError{kmip.ReasonWrongKeyLifecycleState, ke.Msg}
		case kms.ErrInvalid:
			return &opError{kmip.ReasonInvalidField, ke.Msg}
		case kms.ErrUnsupported:
			return &opError{kmip.ReasonOperationNotSupported, ke.Msg}
		case kms.ErrUnavailable:
			return &opError{kmip.ReasonGeneralFailure, ke.Msg}
		}
	}
	return &opError{kmip.ReasonGeneralFailure, "internal error"}
}

func bad(msg string) *opError { return &opError{kmip.ReasonInvalidField, msg} }

func (s *Server) dispatch(p kms.Principal, v kmip.Version, op uint32, pl *kmip.Item) (*kmip.Item, *opError) {
	switch op {
	case kmip.OpDiscoverVersions:
		return s.discover(pl), nil
	case kmip.OpQuery:
		return s.query(), nil
	case kmip.OpCreate:
		return s.create(p, v, pl)
	case kmip.OpCreateKeyPair:
		return s.createPair(p, v, pl)
	case kmip.OpLocate:
		return s.locate(p, v, pl)
	case kmip.OpGetAttributes:
		return s.getAttributes(p, v, pl)
	case kmip.OpGet:
		return s.get(p, pl)
	case kmip.OpActivate, kmip.OpDestroy, kmip.OpReKey, kmip.OpRevoke:
		return s.lifecycle(p, op, pl)
	case kmip.OpAddAttribute, kmip.OpDeleteAttribute:
		return s.names(p, v, op, pl)
	}
	return nil, &opError{kmip.ReasonOperationNotSupported, "operation is not supported"}
}

func uidResponse(id string) *kmip.Item {
	return kmip.Struct(kmip.TagResponsePayload, kmip.Text(kmip.TagUniqueIdentifier, id))
}

func (s *Server) discover(pl *kmip.Item) *kmip.Item {
	asked := map[kmip.Version]bool{}
	for _, pv := range pl.All(kmip.TagProtocolVersion) {
		if a, b := pv.Child(kmip.TagProtocolVersionMajor), pv.Child(kmip.TagProtocolVersionMinor); a != nil && b != nil {
			asked[kmip.Version{Major: int(a.Num), Minor: int(b.Num)}] = true
		}
	}
	out := kmip.Struct(kmip.TagResponsePayload)
	for _, sv := range supportedVersions {
		if len(asked) == 0 || asked[sv] {
			out.Children = append(out.Children, kmip.Struct(kmip.TagProtocolVersion,
				kmip.Int(kmip.TagProtocolVersionMajor, i32(sv.Major)), kmip.Int(kmip.TagProtocolVersionMinor, i32(sv.Minor))))
		}
	}
	return out
}

func (s *Server) query() *kmip.Item {
	ops := []uint32{kmip.OpDiscoverVersions, kmip.OpQuery, kmip.OpCreate, kmip.OpCreateKeyPair, kmip.OpLocate, kmip.OpGet, kmip.OpGetAttributes,
		kmip.OpActivate, kmip.OpRevoke, kmip.OpDestroy, kmip.OpReKey, kmip.OpAddAttribute, kmip.OpDeleteAttribute}
	sort.Slice(ops, func(i, j int) bool { return ops[i] < ops[j] })
	out := kmip.Struct(kmip.TagResponsePayload)
	for _, o := range ops {
		out.Children = append(out.Children, kmip.Enum(kmip.TagOperation, o))
	}
	for _, t := range []uint32{kmip.ObjSymmetricKey, kmip.ObjPublicKey, kmip.ObjPrivateKey} {
		out.Children = append(out.Children, kmip.Enum(kmip.TagObjectType, t))
	}
	out.Children = append(out.Children, kmip.Text(kmip.TagVendorIdentification, "pqc-kms"))
	return out
}

// i32 converts to the 32-bit integer of the KMIP encoding, saturating instead of wrapping.
func i32(n int) int32 {
	if n > 1<<31-1 {
		return 1<<31 - 1
	}
	if n < -1<<31 {
		return -1 << 31
	}
	return int32(n)
}

// shortHandshake keeps the reason of a failed handshake without echoing peer-controlled text at length.
func shortHandshake(err error) string {
	m := err.Error()
	if len(m) > 160 {
		m = m[:160]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, m)
}
