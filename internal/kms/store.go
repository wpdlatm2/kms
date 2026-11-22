package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wpdlatm2/localhsm"
)

// Sealer encrypts the whole database at rest (authenticated): the stored file reveals neither key
// values nor metadata, and any modification is detected.
type Sealer interface {
	Name() string
	Seal(aad, plaintext []byte) ([]byte, error)
	Open(aad, blob []byte) ([]byte, error)
}

// ---- file key sealer (development, or hosts without a TPM)

// FileSealer uses AES-256-GCM with a 32-byte key kept in a file (mode 0600).
type FileSealer struct{ gcm cipher.AEAD }

// LoadFileSealer reads the key file, creating it (random key) when it does not exist.
func LoadFileSealer(path string) (*FileSealer, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key file %s must be exactly 32 bytes", path)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	return &FileSealer{g}, err
}

func (f *FileSealer) Name() string { return "file-key (AES-256-GCM)" }
func (f *FileSealer) Seal(aad, pt []byte) ([]byte, error) {
	n := make([]byte, f.gcm.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return f.gcm.Seal(n, n, pt, aad), nil
}
func (f *FileSealer) Open(aad, blob []byte) ([]byte, error) {
	ns := f.gcm.NonceSize()
	if len(blob) < ns+16 {
		return nil, errors.New("sealed data is too short")
	}
	return f.gcm.Open(nil, blob[:ns], blob[ns:], aad)
}

// ---- localhsm sealer (master key inside a TPM-protected localhsm keystore)

// HSMSealer encrypts the database with an AES-256-GCM key that lives in a localhsm keystore, whose own
// master key is bound to the platform TPM.
type HSMSealer struct {
	h  *localhsm.HSM
	id string
}

// OpenHSMSealer opens (or creates) the keystore at ksPath protected by the TPM key tpmName and makes sure
// the sealing key exists. allowSoftware permits a software protector on hosts without TPM (not for production).
func OpenHSMSealer(ksPath, tpmName string, allowSoftware bool) (*HSMSealer, error) {
	p, err := localhsm.AvailableProtector(tpmName, allowSoftware)
	if err != nil {
		return nil, err
	}
	var h *localhsm.HSM
	if _, statErr := os.Stat(ksPath); errors.Is(statErr, os.ErrNotExist) {
		h, err = localhsm.CreateWith(ksPath, p, localhsm.CreateOptions{})
	} else {
		h, err = localhsm.Open(ksPath, p)
	}
	if err != nil {
		return nil, err
	}
	const id = "kms-database"
	if _, ok := h.ListKeys()[id]; !ok {
		if err := h.GenerateKey(id, localhsm.AES256GCM); err != nil {
			return nil, err
		}
	}
	return &HSMSealer{h: h, id: id}, nil
}

func (s *HSMSealer) Name() string { return "localhsm (TPM-bound master key)" }
func (s *HSMSealer) Seal(aad, pt []byte) ([]byte, error) {
	return s.h.Encrypt(s.id, pt, aad)
}
func (s *HSMSealer) Open(aad, blob []byte) ([]byte, error) {
	return s.h.Decrypt(s.id, blob, aad)
}

// ---- database

const dbAAD = "pqc-kms database v1"

type dbFile struct {
	Version   int         `json:"version"`
	Objects   []*Object   `json:"objects"`
	Groups    []*Group    `json:"groups"`
	Templates []*Template `json:"templates"`
	Bindings  []Binding   `json:"bindings"`
	Managers  []Manager   `json:"managers"`
}

// Store keeps all objects in memory and persists them, sealed, after every change.
type Store struct {
	mu   sync.RWMutex
	path string
	seal Sealer
	objs map[string]*Object

	groups    map[string]*Group
	templates map[string]*Template
	bindings  []Binding
	managers  []Manager
}

// OpenStore loads the database (empty when the file does not exist). A file that fails authentication
// (wrong master key or tampering) is an error, never silently replaced.
func OpenStore(path string, s Sealer) (*Store, error) {
	st := &Store{path: path, seal: s, objs: map[string]*Object{}, groups: map[string]*Group{}, templates: map[string]*Template{}}
	blob, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		st.defaults()
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	pt, err := s.Open([]byte(dbAAD), blob)
	if err != nil {
		return nil, fmt.Errorf("kms database %s cannot be opened (wrong master key, or the file was modified): %w", path, err)
	}
	defer clear(pt)
	var db dbFile
	if err := json.Unmarshal(pt, &db); err != nil {
		return nil, fmt.Errorf("kms database: %w", err)
	}
	for _, o := range db.Objects {
		st.objs[o.ID] = o
	}
	for _, g := range db.Groups {
		st.groups[g.Name] = g
	}
	for _, t := range db.Templates {
		st.templates[t.Name] = t
	}
	st.bindings = db.Bindings
	st.managers = db.Managers
	st.defaults()
	return st, nil
}

// defaults makes sure the built-in group and templates exist.
func (s *Store) defaults() {
	if s.groups[GroupAll] == nil {
		s.groups[GroupAll] = &Group{Name: GroupAll, Kind: KindAll, Description: "모든 그룹에 적용되는 특수 그룹 (여기에 매핑된 클라이언트는 그룹과 무관하게 해당 템플릿 권한을 가짐)", Builtin: true, Created: now()}
	}
	if s.templates["owner"] == nil {
		s.templates["owner"] = &Template{Name: "owner", Description: "생성·조회·수정·삭제 (CRUD)", Builtin: true,
			Operations: []string{"create", "locate", "getattributes", "get", "activate", "revoke", "rekey", "setattribute", "destroy"}}
	}
	if s.templates["guest"] == nil {
		s.templates["guest"] = &Template{Name: "guest", Description: "조회만 (R)", Builtin: true, Operations: []string{"locate", "getattributes", "get"}}
	}
}

// save must be called with the write lock held.
func (s *Store) save() error {
	db := dbFile{Version: 1}
	for _, o := range s.objs {
		db.Objects = append(db.Objects, o)
	}
	for _, g := range s.groups {
		db.Groups = append(db.Groups, g)
	}
	for _, t := range s.templates {
		db.Templates = append(db.Templates, t)
	}
	db.Bindings = s.bindings
	db.Managers = s.managers
	pt, err := json.Marshal(&db)
	if err != nil {
		return err
	}
	defer clear(pt)
	blob, err := s.seal.Seal([]byte(dbAAD), pt)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if _, err := os.Stat(s.path); err == nil { // keep one previous generation
		_ = os.Rename(s.path, s.path+".prev")
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Dir() string { return filepath.Dir(s.path) }

func now() int64 { return time.Now().Unix() }
