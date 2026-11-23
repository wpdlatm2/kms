package kmipsrv

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wpdlatm2/localhsm/kmip"
	"github.com/wpdlatm2/kms/internal/kms"
)

// ---- helpers

func (e *env) raw(cn string) *tls.Conn {
	e.t.Helper()
	c, err := tls.Dial("tcp", e.addr, e.pki.ClientTLS(cn))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.Close() })
	return c
}

func header(tag kmip.Tag, typ byte, length uint32) []byte {
	b := []byte{byte(tag >> 16), byte(tag >> 8), byte(tag), typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[4:], length)
	return b
}

// alive proves the server still serves a valid request on a fresh connection.
func (e *env) alive() {
	e.t.Helper()
	c := e.dial("app", kmip.Version{Major: 2, Minor: 1})
	id, err := c.Create(append(kmip.AlgorithmAttrs(kmip.AlgAES, 128, 0), kmip.ObjectGroupAttr("payments")))
	if err != nil || id == "" {
		e.t.Fatalf("the server stopped answering after abuse: %v", err)
	}
}

// ---- malformed input never crashes or wedges the server

func TestGS_KMIPMalformedFrames(t *testing.T) {
	e := start(t)
	deep := kmip.Text(kmip.TagUsername, "x")
	for i := 0; i < 60; i++ {
		deep = kmip.Struct(kmip.TagRequestMessage, deep)
	}
	deepB, _ := deep.Encode()
	rnd := make([]byte, 4096)
	rand.New(rand.NewSource(1)).Read(rnd)

	cases := map[string][]byte{
		"empty":                   {},
		"one byte":                {0x42},
		"header only":             header(kmip.TagRequestMessage, 0x01, 0),
		"length larger than data": append(header(kmip.TagRequestMessage, 0x01, 1000), 1, 2, 3),
		"absurd length 4 GiB":     header(kmip.TagRequestMessage, 0x01, 0xFFFFFFFF),
		"length over the cap":     header(kmip.TagRequestMessage, 0x01, 2<<20),
		"not a structure":         append(header(kmip.TagRequestMessage, 0x02, 4), 0, 0, 0, 1, 0, 0, 0, 0),
		"unknown item type":       append(header(kmip.TagRequestMessage, 0x77, 0), 0),
		"nesting bomb":            deepB,
		"random bytes":            rnd,
		"all 0xFF":                {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		"all zero":                make([]byte, 64),
		"http request":            []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
	}
	for name, payload := range cases {
		c := e.raw("app")
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write(payload)
		buf := make([]byte, 4096)
		_, _ = c.Read(buf) // either an error message or a closed connection: never a hang past the deadline
		c.Close()
		e.alive()
		t.Logf("%-28s ok", name)
	}
}

func TestGS_KMIPStructureViolations(t *testing.T) {
	e := start(t)
	c := e.dial("app", kmip.Version{Major: 2, Minor: 1})
	_ = c
	p := kms.ClientPrincipal("app")
	bad := []*kmip.Item{
		kmip.Struct(kmip.TagRequestMessage),                                                                           // no header
		kmip.Struct(kmip.TagRequestMessage, kmip.Struct(kmip.TagRequestHeader)),                                       // no version
		kmip.Struct(kmip.TagRequestMessage, kmip.Struct(kmip.TagRequestHeader, kmip.Struct(kmip.TagProtocolVersion))), // empty version
		kmip.Struct(kmip.TagRequestMessage,
			kmip.Struct(kmip.TagRequestHeader, kmip.Struct(kmip.TagProtocolVersion, kmip.Int(kmip.TagProtocolVersionMajor, 2), kmip.Int(kmip.TagProtocolVersionMinor, 1))),
		), // no batch
		kmip.Struct(kmip.TagResponseMessage), // wrong message type
	}
	for i, it := range bad {
		b, _ := it.Encode()
		out := e.srv.handle(p, "test", b)
		if _, _, err := kmip.Decode(out); err != nil {
			t.Fatalf("case %d: the answer is not valid TTLV: %v", i, err)
		}
	}
	// wrong value types where the server expects other types must not panic
	mk := func(ver kmip.Version, op uint32, payload *kmip.Item) *kmip.Item {
		return kmip.Struct(kmip.TagRequestMessage,
			kmip.Struct(kmip.TagRequestHeader, kmip.Struct(kmip.TagProtocolVersion, kmip.Int(kmip.TagProtocolVersionMajor, int32(ver.Major)), kmip.Int(kmip.TagProtocolVersionMinor, int32(ver.Minor))), kmip.Int(kmip.TagBatchCount, 1)),
			kmip.Struct(kmip.TagBatchItem, kmip.Enum(kmip.TagOperation, op), payload))
	}
	for _, ver := range []kmip.Version{{Major: 1, Minor: 4}, {Major: 2, Minor: 1}, {Major: 3, Minor: 0}, {Major: 9, Minor: 9}, {Major: 0, Minor: 0}} {
		for _, op := range []uint32{kmip.OpCreate, kmip.OpCreateKeyPair, kmip.OpLocate, kmip.OpGet, kmip.OpGetAttributes, kmip.OpActivate, kmip.OpRevoke, kmip.OpDestroy, kmip.OpReKey, kmip.OpAddAttribute, kmip.OpDeleteAttribute, kmip.OpQuery, kmip.OpDiscoverVersions, 0x7FFF} {
			for _, pl := range []*kmip.Item{
				kmip.Struct(kmip.TagRequestPayload),
				kmip.Struct(kmip.TagRequestPayload, kmip.Int(kmip.TagUniqueIdentifier, 5)),                                  // integer where text belongs
				kmip.Struct(kmip.TagRequestPayload, kmip.Text(kmip.TagUniqueIdentifier, string(make([]byte, 5000)))),        // long id
				kmip.Struct(kmip.TagRequestPayload, kmip.Text(kmip.TagObjectType, "x"), kmip.Text(kmip.TagAttributes, "y")), // wrong types
				kmip.Struct(kmip.TagRequestPayload, kmip.Struct(kmip.TagAttributes, kmip.Text(kmip.TagCryptographicAlgorithm, "z"), kmip.Text(kmip.TagCryptographicLength, "w"))),
				kmip.Struct(kmip.TagRequestPayload, kmip.Enum(kmip.TagObjectType, 99), kmip.Struct(kmip.TagAttributes)),
				kmip.Struct(kmip.TagRequestPayload, kmip.Struct(kmip.TagRevocationReason, kmip.Text(kmip.TagRevocationReasonCode, "q"))),
			} {
				b, _ := mk(ver, op, pl).Encode()
				out := e.srv.handle(p, "test", b)
				if _, _, err := kmip.Decode(out); err != nil {
					t.Fatalf("v%s op %#x: answer is not valid TTLV: %v", ver, op, err)
				}
			}
		}
	}
	e.alive()
}

func TestGS_KMIPBatchCap(t *testing.T) {
	e := start(t)
	p := kms.ClientPrincipal("app")
	items := []*kmip.Item{kmip.Struct(kmip.TagRequestHeader, kmip.Struct(kmip.TagProtocolVersion, kmip.Int(kmip.TagProtocolVersionMajor, 2), kmip.Int(kmip.TagProtocolVersionMinor, 1)))}
	for i := 0; i < maxBatch+1; i++ {
		items = append(items, kmip.Struct(kmip.TagBatchItem, kmip.Enum(kmip.TagOperation, kmip.OpQuery), kmip.Struct(kmip.TagRequestPayload)))
	}
	b, _ := kmip.Struct(kmip.TagRequestMessage, items...).Encode()
	out, _, _ := kmip.Decode(e.srv.handle(p, "t", b))
	bi := out.Child(kmip.TagBatchItem)
	if bi == nil || bi.Child(kmip.TagResultStatus) == nil || bi.Child(kmip.TagResultStatus).Uint() == kmip.StatusSuccess {
		t.Fatal("an oversized batch was processed")
	}
	// exactly the cap is fine
	b, _ = kmip.Struct(kmip.TagRequestMessage, items[:maxBatch+1]...).Encode()
	out, _, _ = kmip.Decode(e.srv.handle(p, "t", b))
	if len(out.All(kmip.TagBatchItem)) != maxBatch {
		t.Fatalf("a batch of %d operations got %d answers", maxBatch, len(out.All(kmip.TagBatchItem)))
	}
}

func TestGS_KMIPSlowClientIsCutOff(t *testing.T) {
	old := MessageTimeout
	MessageTimeout = 400 * time.Millisecond
	defer func() { MessageTimeout = old }()
	e := start(t)
	c := e.raw("app")
	// a header that promises 100 bytes, then silence
	_, _ = c.Write(header(kmip.TagRequestMessage, 0x01, 100))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	buf := make([]byte, 16)
	_, err := c.Read(buf)
	if err == nil {
		t.Fatal("the server answered an incomplete message")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the stalled connection was not closed by the server within 3 s")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the stalled connection lived %v", time.Since(start))
	}
	e.alive()
}

func TestGS_KMIPManyConnections(t *testing.T) {
	e := start(t)
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := kmip.Dial(context.Background(), kmip.Config{Addr: e.addr, TLS: e.pki.ClientTLS("app"), Version: kmip.Version{Major: 2, Minor: 1}, Timeout: 20 * time.Second})
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			for j := 0; j < 3; j++ {
				if _, err := c.Create(append(kmip.AlgorithmAttrs(kmip.AlgAES, 128, 0), kmip.ObjectGroupAttr("payments"))); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent clients: %v", err)
	}
	if n := len(e.svc.List(e.svc.AdminPrincipal("root"), kms.Filter{})); n != 450 {
		t.Fatalf("expected 450 keys, found %d", n)
	}
}

// ---- fuzzing: whatever arrives, the handler answers with valid TTLV and never panics

func fuzzSrv(tb testing.TB) (*Server, kms.Principal) {
	dir := tb.TempDir()
	sl, err := kms.LoadFileSealer(dir + "/m.key")
	if err != nil {
		tb.Fatal(err)
	}
	st, err := kms.OpenStore(dir+"/kms.db", sl)
	if err != nil {
		tb.Fatal(err)
	}
	svc := kms.NewService(st, []string{"root"})
	root := svc.AdminPrincipal("root")
	if err := svc.PutGroup(root, kms.GroupReq{Owner: "tester", Name: "payments", Kind: kms.KindService}, true); err != nil {
		tb.Fatal(err)
	}
	if err := svc.PutBinding(root, "app", "payments", "owner", kms.GrantInfo{Approval: "APR-T1", Owner: "tester"}); err != nil {
		tb.Fatal(err)
	}
	return &Server{Svc: svc}, kms.ClientPrincipal("app")
}

func FuzzKMIPRequest(f *testing.F) {
	valid := func(ver kmip.Version, op uint32) []byte {
		b, _ := kmip.Struct(kmip.TagRequestMessage,
			kmip.Struct(kmip.TagRequestHeader, kmip.Struct(kmip.TagProtocolVersion, kmip.Int(kmip.TagProtocolVersionMajor, int32(ver.Major)), kmip.Int(kmip.TagProtocolVersionMinor, int32(ver.Minor))), kmip.Int(kmip.TagBatchCount, 1)),
			kmip.Struct(kmip.TagBatchItem, kmip.Enum(kmip.TagOperation, op), kmip.Struct(kmip.TagRequestPayload, kmip.Text(kmip.TagUniqueIdentifier, "abc"), kmip.Struct(kmip.TagAttributes, kmip.Enum(kmip.TagCryptographicAlgorithm, kmip.AlgAES), kmip.Int(kmip.TagCryptographicLength, 256))))).Encode()
		return b
	}
	for _, v := range []kmip.Version{{Major: 1, Minor: 4}, {Major: 2, Minor: 1}} {
		for _, op := range []uint32{kmip.OpCreate, kmip.OpLocate, kmip.OpGet, kmip.OpGetAttributes, kmip.OpActivate, kmip.OpRevoke, kmip.OpDestroy, kmip.OpReKey, kmip.OpAddAttribute, kmip.OpQuery, kmip.OpDiscoverVersions, kmip.OpCreateKeyPair} {
			f.Add(valid(v, op))
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x42, 0x00, 0x78, 0x01, 0xff, 0xff, 0xff, 0xff})
	srv, p := fuzzSrv(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		out := srv.handle(p, "fuzz", data)
		if _, _, err := kmip.Decode(out); err != nil {
			t.Fatalf("the answer is not valid TTLV: %v", err)
		}
	})
}
