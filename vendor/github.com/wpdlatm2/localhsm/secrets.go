package localhsm

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// SecretStore keeps small secrets (KMS API keys, tokens, passwords, enrollment tokens) in a node-local
// file. All entries are AES-256-GCM encrypted under one data key, and that data key is wrapped by a
// Protector (TPM-bound on a TPM node). The data key is unwrapped for each operation and zeroized
// again, so a Get costs one TPM call (tens of milliseconds): read credentials rarely.
//
// A secret that has to be presented to a remote service is in memory in clear while it is used;
// prefer using it only to obtain short-lived tokens. For client-certificate authentication use a
// TPMSigner instead: that key never leaves the TPM.
type SecretStore struct {
	mu   sync.Mutex
	path string
	prot Protector
	id   string
	doc  secretFile
}

type secretEntry struct {
	Nonce   []byte `json:"nonce"`
	CT      []byte `json:"ct"`
	Created int64  `json:"created"`
}

type secretFile struct {
	Version    int                     `json:"version"`
	Protector  string                  `json:"protector"`
	Recipient  string                  `json:"recipient"`
	WrappedKey []byte                  `json:"wrapped_key"`
	Secrets    map[string]*secretEntry `json:"secrets"`
}

// ErrNoSecret: no secret with that name.
var ErrNoSecret = errors.New("localhsm: no such secret")

// OpenSecretStore opens the store at path, creating it (with a fresh data key wrapped by p) if the
// file does not exist. The store is bound to p's key: another node or another TPM cannot open it.
func OpenSecretStore(path string, p Protector) (*SecretStore, error) {
	id, _, err := p.Recipient()
	if err != nil {
		return nil, err
	}
	s := &SecretStore{path: path, prot: p, id: id}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &s.doc); err != nil {
			return nil, fmt.Errorf("localhsm: corrupt secret store: %w", err)
		}
		if s.doc.Version != 1 {
			return nil, errors.New("localhsm: unsupported secret store version")
		}
		if s.doc.Recipient != id {
			return nil, errors.New("localhsm: this secret store belongs to a different node/key")
		}
		if s.doc.Secrets == nil {
			s.doc.Secrets = map[string]*secretEntry{}
		}
	case os.IsNotExist(err):
		dek := make([]byte, 32)
		if _, err := rand.Read(dek); err != nil {
			return nil, err
		}
		defer clear(dek)
		w, err := p.Wrap(dek)
		if err != nil {
			return nil, err
		}
		s.doc = secretFile{Version: 1, Protector: p.Name(), Recipient: id, WrappedKey: w, Secrets: map[string]*secretEntry{}}
		if err := s.save(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return s, nil
}

func (s *SecretStore) save() error {
	b, err := json.MarshalIndent(&s.doc, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *SecretStore) aad(name string) []byte {
	return []byte("localhsm-secret|" + s.id + "|" + name)
}

// Put stores (or replaces) a secret.
func (s *SecretStore) Put(name string, value []byte) error {
	if name == "" {
		return errors.New("localhsm: empty secret name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dek, err := s.prot.Unwrap(s.doc.WrappedKey)
	if err != nil {
		return err
	}
	defer clear(dek)
	g, err := newGCM(dek)
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	old := s.doc.Secrets[name]
	s.doc.Secrets[name] = &secretEntry{Nonce: nonce, CT: g.Seal(nil, nonce, value, s.aad(name)), Created: time.Now().Unix()}
	if err := s.save(); err != nil {
		s.doc.Secrets[name] = old
		if old == nil {
			delete(s.doc.Secrets, name)
		}
		return err
	}
	return nil
}

// Get returns a copy of the secret. The caller should clear() it after use.
func (s *SecretStore) Get(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.doc.Secrets[name]
	if e == nil {
		return nil, ErrNoSecret
	}
	dek, err := s.prot.Unwrap(s.doc.WrappedKey)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	g, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, e.Nonce, e.CT, s.aad(name))
	if err != nil {
		return nil, errors.New("localhsm: secret decryption failed (corrupted or moved entry)")
	}
	return pt, nil
}

// Delete removes a secret.
func (s *SecretStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.doc.Secrets[name]
	if old == nil {
		return ErrNoSecret
	}
	delete(s.doc.Secrets, name)
	if err := s.save(); err != nil {
		s.doc.Secrets[name] = old
		return err
	}
	return nil
}

// Names lists the stored secret names (never the values).
func (s *SecretStore) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.doc.Secrets))
	for n := range s.doc.Secrets {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Destroy deletes the file and the protector's key (crypto-erase of every secret in it).
func (s *SecretStore) Destroy() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.prot.Destroy()
	if e := os.Remove(s.path); e != nil && !os.IsNotExist(e) && err == nil {
		err = e
	}
	return err
}
