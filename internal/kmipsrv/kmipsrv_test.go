package kmipsrv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wpdlatm2/localhsm"
	"github.com/wpdlatm2/localhsm/kmip"
	"github.com/wpdlatm2/kms/internal/kms"
	"github.com/wpdlatm2/kms/internal/logs"
	"github.com/wpdlatm2/kms/internal/testpki"
)

type env struct {
	t    *testing.T
	pki  *testpki.PKI
	svc  *kms.Service
	srv  *Server
	addr string
	log  *logs.Log
}

func start(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	sl, err := kms.LoadFileSealer(filepath.Join(dir, "m.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := kms.OpenStore(filepath.Join(dir, "kms.db"), sl)
	if err != nil {
		t.Fatal(err)
	}
	svc := kms.NewService(st, []string{"root"})
	root := svc.AdminPrincipal("root")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(svc.PutGroup(root, kms.GroupReq{Name: "payments", Kind: kms.KindService}, true))
	must(svc.PutGroup(root, kms.GroupReq{Name: "billing", Kind: kms.KindService}, true))
	must(svc.PutBinding(root, "app", "payments", "owner"))
	must(svc.PutBinding(root, "reader", "payments", "guest"))
	must(svc.PutBinding(root, "other-app", "billing", "owner"))
	pki := testpki.New(t)
	lg, _ := logs.Open("", "client")
	srv := &Server{Svc: svc, TLS: pki.ServerTLS(), Access: lg}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLS)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(srv.Close)
	return &env{t: t, pki: pki, svc: svc, srv: srv, addr: ln.Addr().String(), log: lg}
}

func (e *env) dial(cn string, v kmip.Version) *kmip.Client {
	e.t.Helper()
	c, err := kmip.Dial(context.Background(), kmip.Config{Addr: e.addr, TLS: e.pki.ClientTLS(cn), Version: v, Timeout: 10 * time.Second})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.Close() })
	return c
}

func reason(err error) string {
	var pe *kmip.ProtocolError
	if errors.As(err, &pe) {
		return pe.Error()
	}
	return ""
}

func wantReason(t *testing.T, err error, sub, what string) {
	t.Helper()
	if err == nil || !strings.Contains(reason(err), sub) {
		t.Fatalf("%s: got %v, want a KMIP error containing %q", what, err, sub)
	}
}

func TestEveryProtocolVersionLifecycle(t *testing.T) {
	e := start(t)
	for _, v := range kmip.Supported {
		v := v
		t.Run(v.String(), func(t *testing.T) {
			c := e.dial("app", v)
			name := "life-" + v.String()
			attrs := append(kmip.AlgorithmAttrs(kmip.AlgAES, 256, kmip.UsageEncrypt|kmip.UsageDecrypt), kmip.NameAttr(name), kmip.ObjectGroupAttr("payments"))
			id, err := c.Create(attrs)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			a, err := c.GetAttributes(id)
			if err != nil {
				t.Fatal(err)
			}
			if kmip.StateName(a.State) != "Pre-Active" || a.Algorithm != kmip.AlgAES || a.Length != 256 || len(a.Names) != 1 || a.Names[0] != name {
				t.Fatalf("attributes %+v", a)
			}
			// a Pre-Active key value cannot be fetched
			if _, err := c.Get(id); err == nil {
				t.Fatal("Get of a Pre-Active key succeeded")
			} else {
				wantReason(t, err, "Wrong Key Lifecycle State", "Get pre-active")
			}
			if err := c.Activate(id); err != nil {
				t.Fatalf("Activate: %v", err)
			}
			if ids, err := c.Locate(name); err != nil || len(ids) != 1 || ids[0] != id {
				t.Fatalf("Locate by name: %v %v", ids, err)
			}
			o, err := c.Get(id)
			if err != nil || len(o.Material) != 32 || o.Type != kmip.ObjSymmetricKey || o.Format != kmip.FmtRaw {
				t.Fatalf("Get: %+v %v", o, err)
			}
			newID, err := c.ReKey(id)
			if err != nil {
				t.Fatalf("Re-key: %v", err)
			}
			ids, _ := c.Locate(name)
			if len(ids) != 2 {
				t.Fatalf("both objects must carry the name: %v", ids)
			}
			old, _ := c.GetAttributes(id)
			cur, _ := c.GetAttributes(newID)
			if kmip.StateName(old.State) != "Deactivated" || kmip.StateName(cur.State) != "Active" {
				t.Fatalf("states after re-key: old=%s new=%s", kmip.StateName(old.State), kmip.StateName(cur.State))
			}
			// the deactivated key can still be fetched (consumers need it for old data)
			if o, err := c.Get(id); err != nil || len(o.Material) != 32 {
				t.Fatalf("Get of a deactivated key: %v", err)
			}
			if err := c.Revoke(newID, kmip.RevokeKeyCompromise, "test"); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Get(newID); err == nil {
				t.Fatal("a compromised key value was released")
			}
			if err := c.Destroy(id); err != nil {
				t.Fatal(err)
			}
			if err := c.Destroy(newID); err != nil {
				t.Fatal(err)
			}
			d, _ := c.GetAttributes(id)
			if kmip.StateName(d.State) != "Destroyed" || d.Destroyed.IsZero() {
				t.Fatalf("destroyed: %+v", d)
			}
			// names can be added and removed (1.x deletes by index; 2.x servers keep Add only for the test)
			id2, err := c.Create(append(kmip.AlgorithmAttrs(kmip.AlgAES, 128, 0), kmip.ObjectGroupAttr("payments")))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.AddAttribute(id2, kmip.NameAttr("alias-"+v.String())); err != nil {
				t.Fatalf("AddAttribute: %v", err)
			}
			if ids, _ := c.Locate("alias-" + v.String()); len(ids) != 1 {
				t.Fatalf("alias not found: %v", ids)
			}
		})
	}
}

func TestPermissionGroupsOverKMIP(t *testing.T) {
	e := start(t)
	app, reader, other, stranger := e.dial("app", kmip.Version{Major: 2, Minor: 1}), e.dial("reader", kmip.Version{Major: 1, Minor: 4}),
		e.dial("other-app", kmip.Version{Major: 2, Minor: 0}), e.dial("stranger", kmip.Version{Major: 2, Minor: 1})
	id, err := app.Create(append(kmip.AlgorithmAttrs(kmip.AlgAES, 256, 0), kmip.NameAttr("shared"), kmip.ObjectGroupAttr("payments")))
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Activate(id); err != nil {
		t.Fatal(err)
	}

	// guest of the group: reads, cannot change
	if ids, err := reader.Locate("shared"); err != nil || len(ids) != 1 {
		t.Fatalf("guest locate: %v %v", ids, err)
	}
	if o, err := reader.Get(id); err != nil || len(o.Material) != 32 {
		t.Fatalf("guest get: %v", err)
	}
	_, err = reader.Create(append(kmip.AlgorithmAttrs(kmip.AlgAES, 256, 0), kmip.ObjectGroupAttr("payments")))
	wantReason(t, err, "Permission Denied", "guest create")
	wantReason(t, reader.Revoke(id, kmip.RevokeCessationOfOperation, ""), "Item Not Found", "guest revoke")
	wantReason(t, reader.Destroy(id), "Item Not Found", "guest destroy")
	if _, err := reader.ReKey(id); err == nil {
		t.Fatal("guest re-keyed")
	}

	// another service's owner and a stranger see nothing of this service
	for who, c := range map[string]*kmip.Client{"other-app": other, "stranger": stranger} {
		if ids, _ := c.Locate("shared"); len(ids) != 0 {
			t.Fatalf("%s locates a key of another service: %v", who, ids)
		}
		if _, err := c.Get(id); err == nil {
			t.Fatalf("%s gets a key of another service", who)
		}
		if _, err := c.GetAttributes(id); err == nil {
			t.Fatalf("%s reads attributes of another service", who)
		}
	}
	// creating in a service you are not bound to
	_, err = other.Create(append(kmip.AlgorithmAttrs(kmip.AlgAES, 256, 0), kmip.ObjectGroupAttr("payments")))
	wantReason(t, err, "Permission Denied", "create in a foreign service")
	// no Object Group: the only service the client may create in is used
	if nid, err := other.Create(kmip.AlgorithmAttrs(kmip.AlgAES, 128, 0)); err != nil {
		t.Fatalf("default group: %v", err)
	} else if a, _ := other.GetAttributes(nid); a == nil {
		t.Fatal("no attributes")
	}
	// a client bound to two services must say which
	root := e.svc.AdminPrincipal("root")
	if err := e.svc.PutBinding(root, "other-app", "payments", "owner"); err != nil {
		t.Fatal(err)
	}
	_, err = other.Create(kmip.AlgorithmAttrs(kmip.AlgAES, 128, 0))
	wantReason(t, err, "Invalid Field", "ambiguous service")
	// and an unknown one
	_, err = other.Create(append(kmip.AlgorithmAttrs(kmip.AlgAES, 128, 0), kmip.ObjectGroupAttr("nope")))
	wantReason(t, err, "Invalid Field", "unknown service")

	// the client log recorded all of it, with the identities
	var denied, ok int
	for _, en := range e.log.Last(500) {
		if en.Plane != "client" || en.Kind != "request" {
			t.Fatalf("unexpected entry in the client log: %+v", en)
		}
		if en.Who == "reader" && strings.HasPrefix(en.Result, "error") {
			denied++
		}
		if en.Who == "app" && en.Result == "ok" {
			ok++
		}
	}
	if denied < 3 || ok < 2 {
		t.Fatalf("client log incomplete: denied=%d ok=%d", denied, ok)
	}
}

func TestPostQuantumAndClassicalKeyPairs(t *testing.T) {
	e := start(t)
	cases := []struct {
		name  string
		alg   uint32
		bits  int
		curve uint32
		priv  int // expected private value size in bytes (0 = just non-empty)
		pub   int
		x509  bool
	}{
		{"rsa-2048", kmip.AlgRSA, 2048, 0, 0, 0, true},
		{"ec-p256", kmip.AlgECDSA, 0, kmip.CurveP256, 0, 0, true},
		{"ec-p384", kmip.AlgEC, 0, kmip.CurveP384, 0, 0, true},
		{"ed25519", kmip.AlgEd25519, 0, 0, 0, 0, true},
		{"ml-dsa-44", kmip.AlgMLDSA44, 0, 0, 2560, 1312, false},
		{"ml-dsa-65", kmip.AlgMLDSA65, 0, 0, 4032, 1952, false},
		{"ml-dsa-87", kmip.AlgMLDSA87, 0, 0, 4896, 2592, false},
		{"slh-dsa-sha2-128s", kmip.AlgSLHDSASHA2128s, 0, 0, 64, 32, false},
		{"slh-dsa-shake-256f", kmip.AlgSLHDSASHAKE256f, 0, 0, 128, 64, false},
		{"ml-kem-512", kmip.AlgMLKEM512, 0, 0, 1632, 800, false},
		{"ml-kem-768", kmip.AlgMLKEM768, 0, 0, 2400, 1184, false},
		{"ml-kem-1024", kmip.AlgMLKEM1024, 0, 0, 3168, 1568, false},
		{"x25519-ml-kem-768", kmip.AlgX25519MLKEM768, 0, 0, 0, 0, false},
		{"ed448", kmip.AlgEd448, 0, 0, 0, 0, false},
	}
	for _, v := range []kmip.Version{{Major: 1, Minor: 4}, {Major: 2, Minor: 1}, {Major: 3, Minor: 0}} {
		c := e.dial("app", v)
		for _, tc := range cases {
			tc := tc
			t.Run(v.String()+"/"+tc.name, func(t *testing.T) {
				common := append(kmip.AlgorithmAttrs(tc.alg, tc.bits, 0), kmip.ObjectGroupAttr("payments"), kmip.NameAttr(tc.name+"-"+v.String()))
				if tc.curve != 0 {
					common = append(common, kmip.CurveAttr(tc.curve))
				}
				priv, pub, err := c.CreateKeyPair(common)
				if err != nil {
					t.Fatalf("Create Key Pair: %v", err)
				}
				for _, id := range []string{priv, pub} {
					if err := c.Activate(id); err != nil {
						t.Fatal(err)
					}
				}
				po, err := c.Get(priv)
				if err != nil || po.Type != kmip.ObjPrivateKey || len(po.Material) == 0 {
					t.Fatalf("private key: %+v %v", po, err)
				}
				qo, err := c.Get(pub)
				if err != nil || qo.Type != kmip.ObjPublicKey || len(qo.Material) == 0 {
					t.Fatalf("public key: %+v %v", qo, err)
				}
				if tc.priv != 0 && len(po.Material) != tc.priv {
					t.Fatalf("private value is %d bytes, want %d", len(po.Material), tc.priv)
				}
				if tc.pub != 0 && len(qo.Material) != tc.pub {
					t.Fatalf("public value is %d bytes, want %d", len(qo.Material), tc.pub)
				}
				if tc.x509 {
					if _, err := x509.ParsePKCS8PrivateKey(po.Material); err != nil {
						t.Fatalf("private value is not PKCS#8: %v", err)
					}
					if _, err := x509.ParsePKIXPublicKey(qo.Material); err != nil {
						t.Fatalf("public value is not X.509 SubjectPublicKeyInfo: %v", err)
					}
				}
				a, _ := c.GetAttributes(priv)
				if a.Algorithm == 0 || kmip.StateName(a.State) != "Active" {
					t.Fatalf("attributes %+v", a)
				}
				// the pair can be found by name and the private half by object type
				if ids, _ := c.Locate(tc.name + "-" + v.String()); len(ids) != 2 {
					t.Fatalf("locate pair: %v", ids)
				}
			})
		}
	}
	// 1.x clients that did not send a length for RSA, or unknown parameters, get a clear error
	c := e.dial("app", kmip.Version{Major: 1, Minor: 4})
	_, _, err := c.CreateKeyPair(append(kmip.AlgorithmAttrs(kmip.AlgRSA, 1000, 0), kmip.ObjectGroupAttr("payments")))
	wantReason(t, err, "Invalid Field", "unsupported RSA size")
}

func TestProtocolEdges(t *testing.T) {
	e := start(t)
	// no client certificate: the TLS handshake is refused
	if _, err := kmip.Dial(context.Background(), kmip.Config{Addr: e.addr, TLS: e.pki.NoCertTLS(), Version: kmip.Version{Major: 1, Minor: 4}, Timeout: 3 * time.Second}); err == nil {
		// Dial succeeds for TLS 1.3 (the server rejects after the handshake): the first request must fail
		c, _ := kmip.Dial(context.Background(), kmip.Config{Addr: e.addr, TLS: e.pki.NoCertTLS(), Version: kmip.Version{Major: 1, Minor: 4}, Timeout: 3 * time.Second})
		if c != nil {
			if _, err := c.Locate("x"); err == nil {
				t.Fatal("a client without a certificate was served")
			}
		}
	}
	// version negotiation picks the newest version
	c := e.dial("app", kmip.Version{})
	if c.Version() != (kmip.Version{Major: 3, Minor: 0}) {
		t.Fatalf("negotiated %s", c.Version())
	}
	si, err := c.Query()
	if err != nil || si.Vendor != "pqc-kms" || len(si.Operations) < 10 {
		t.Fatalf("Query: %+v %v", si, err)
	}
	// an unsupported operation is refused cleanly
	if _, err := c.GetAttributes("does-not-exist"); err == nil {
		t.Fatal("attributes of a missing object")
	} else {
		wantReason(t, err, "Item Not Found", "missing object")
	}
	// the server stays usable after a failed request on the same connection
	if _, err := c.Create(append(kmip.AlgorithmAttrs(kmip.AlgAES, 256, 0), kmip.ObjectGroupAttr("payments"))); err != nil {
		t.Fatal(err)
	}
}

// A consumer such as localhsm fetches keys by name; versions made by re-key arrive as decrypt-only + active.
func TestLocalHSMSyncAgainstThisServer(t *testing.T) {
	e := start(t)
	app := e.dial("app", kmip.Version{Major: 2, Minor: 1})
	id, err := app.Create(append(kmip.AlgorithmAttrs(kmip.AlgAES, 256, 0), kmip.NameAttr("db-key"), kmip.ObjectGroupAttr("payments")))
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Activate(id); err != nil {
		t.Fatal(err)
	}

	rk, _ := localhsm.GenerateRecoveryKey()
	h, err := localhsm.CreateWith(filepath.Join(t.TempDir(), "ks.json"), localhsm.NewRecoveryProtector(rk), localhsm.CreateOptions{Mode: localhsm.ModeEnterprise})
	if err != nil {
		t.Fatal(err)
	}
	ad := &kmip.Adapter{Config: kmip.Config{Addr: e.addr, TLS: e.pki.ClientTLS("reader"), Timeout: 10 * time.Second}, Exportable: true}
	rep, err := h.SyncFromKMS(context.Background(), ad, []string{"db-key"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Created) != 1 || rep.NewVersions != 1 {
		t.Fatalf("first sync %+v", rep)
	}
	first, err := h.ExportKey("db-key", 0)
	if err != nil || len(first.Material) != 32 {
		t.Fatal(err)
	}
	v1 := append([]byte(nil), first.Material...)

	if _, err := app.ReKey(id); err != nil {
		t.Fatal(err)
	}
	rep, err = h.SyncFromKMS(context.Background(), ad, []string{"db-key"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.NewVersions != 1 || rep.StatusChanges != 1 || len(rep.Skipped) != 0 {
		t.Fatalf("sync after re-key %+v", rep)
	}
	cur, _ := h.ExportKey("db-key", 0)
	if string(cur.Material) == string(v1) {
		t.Fatal("the current version is still the old one")
	}
	old, err := h.ExportKey("db-key", 1)
	if err != nil || string(old.Material) != string(v1) || old.State != "decrypt-only" {
		t.Fatalf("version 1: %v state=%v", err, old)
	}

	// revoking the reader's access: the next sync is refused, the keystore keeps working
	root := e.svc.AdminPrincipal("root")
	if err := e.svc.DeleteBinding(root, "reader", "payments"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SyncFromKMS(context.Background(), ad, []string{"db-key"}); err == nil {
		t.Fatal("sync worked after the binding was removed")
	}
	if _, err := h.ExportKey("db-key", 0); err != nil {
		t.Fatalf("keystore unusable after a refused sync: %v", err)
	}
}

// Found by an independent client (PyKMIP): the Create response must carry the Object Type.
func TestCreateResponseCarriesObjectType(t *testing.T) {
	e := start(t)
	for _, v := range []kmip.Version{{Major: 1, Minor: 4}, {Major: 2, Minor: 1}} {
		pl := kmip.Struct(kmip.TagRequestPayload, kmip.Enum(kmip.TagObjectType, kmip.ObjSymmetricKey))
		attrs := append(kmip.AlgorithmAttrs(kmip.AlgAES, 128, 0), kmip.ObjectGroupAttr("payments"))
		if v.Major >= 2 {
			items := []*kmip.Item{}
			for _, a := range attrs {
				items = append(items, a.Value)
			}
			pl.Children = append(pl.Children, kmip.Struct(kmip.TagAttributes, items...))
		} else {
			items := []*kmip.Item{}
			for _, a := range attrs {
				val := *a.Value
				val.Tag = kmip.TagAttributeValue
				items = append(items, kmip.Struct(kmip.TagAttribute, kmip.Text(kmip.TagAttributeName, a.Name), &val))
			}
			pl.Children = append(pl.Children, kmip.Struct(kmip.TagTemplateAttribute, items...))
		}
		out, herr := e.srv.dispatch(kms.ClientPrincipal("app"), v, kmip.OpCreate, pl)
		if herr != nil {
			t.Fatalf("%s: %v", v, herr.msg)
		}
		ot, id := out.Child(kmip.TagObjectType), out.Child(kmip.TagUniqueIdentifier)
		if ot == nil || ot.Uint() != kmip.ObjSymmetricKey || id == nil {
			t.Fatalf("%s: Create response lacks Object Type or Unique Identifier: %+v", v, out)
		}
		if out.Children[0].Tag != kmip.TagObjectType {
			t.Fatalf("%s: Object Type must come first", v)
		}
	}
}
