package logs

import (
	"archive/zip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"
)

// Report is the result of checking the chain of a log.
type Report struct {
	Log        string    `json:"log"`
	OK         bool      `json:"ok"`
	Files      int       `json:"files"`
	Entries    int       `json:"entries"`
	FirstSeq   uint64    `json:"firstSeq"`
	LastSeq    uint64    `json:"lastSeq"`
	LastHash   string    `json:"lastHash"`
	MACChecked bool      `json:"macChecked"`
	From, To   time.Time `json:"-"`
	Problem    string    `json:"problem,omitempty"`
	Where      string    `json:"where,omitempty"`
	CheckedAt  time.Time `json:"checkedAt"`
}

// Verify walks every file in order and checks sequence, chain links, hashes and (when key is given) MACs.
// The first entry of the oldest retained file anchors the chain (older files may have been purged after
// their retention period; the purge itself is recorded in the chain).
func (l *Log) Verify(key []byte) (Report, error) {
	r := Report{Log: l.opt.Name, CheckedAt: time.Now().UTC(), MACChecked: len(key) > 0}
	files, err := l.filesSnapshot()
	if err != nil {
		return r, err
	}
	r.Files = len(files)
	var prev string
	var seq uint64
	first := true
	for _, f := range files {
		name := filepath.Base(f)
		line := 0
		err := scanLines(f, func(b []byte) bool {
			line++
			var e Entry
			if err := json.Unmarshal(b, &e); err != nil {
				r.Problem, r.Where = "unreadable entry", fmt.Sprintf("%s line %d", name, line)
				return false
			}
			if first {
				first = false
				r.FirstSeq = e.Seq
				r.From = e.Time
			} else {
				if e.Seq != seq+1 {
					r.Problem, r.Where = fmt.Sprintf("sequence jumps from %d to %d (entries removed or inserted)", seq, e.Seq), fmt.Sprintf("%s line %d", name, line)
					return false
				}
				if e.Prev != prev {
					r.Problem, r.Where = "chain link does not match the previous entry", fmt.Sprintf("%s line %d (seq %d)", name, line, e.Seq)
					return false
				}
			}
			if hashOf(e) != e.Hash {
				r.Problem, r.Where = "entry content does not match its hash (modified)", fmt.Sprintf("%s line %d (seq %d)", name, line, e.Seq)
				return false
			}
			if len(key) > 0 {
				want, _ := hex.DecodeString(macOf(key, e.Hash))
				got, _ := hex.DecodeString(e.MAC)
				if !hmac.Equal(want, got) {
					r.Problem, r.Where = "MAC does not match (entry was not written by this system, or the key differs)", fmt.Sprintf("%s line %d (seq %d)", name, line, e.Seq)
					return false
				}
			}
			prev, seq = e.Hash, e.Seq
			r.Entries++
			r.To = e.Time
			return true
		})
		if err != nil {
			return r, err
		}
		if r.Problem != "" {
			return r, nil
		}
	}
	r.LastSeq, r.LastHash = seq, prev
	// the live head must be what the files end with, otherwise the tail was cut off
	if hs, hh := l.Head(); l.dir != "" && r.Entries > 0 && (hs != seq || hh != prev) {
		r.Problem, r.Where = fmt.Sprintf("the newest entries are missing (expected seq %d, files end at %d)", hs, seq), "tail"
		return r, nil
	}
	r.OK = true
	return r, nil
}

// Manifest describes an evidence export.
type Manifest struct {
	Log        string    `json:"log"`
	ExportedAt time.Time `json:"exportedAt"`
	ExportedBy string    `json:"exportedBy"`
	Filter     string    `json:"filter"`
	Entries    int       `json:"entries"`
	FirstSeq   uint64    `json:"firstSeq,omitempty"`
	LastSeq    uint64    `json:"lastSeq,omitempty"`
	ChainOK    bool      `json:"chainVerified"`
	Problem    string    `json:"problem,omitempty"`
	ChainHead  string    `json:"chainHead"`
	Algorithm  string    `json:"algorithm"`
	DataSHA256 string    `json:"dataSha256"`
	Note       string    `json:"note"`
}

// Export writes a zip with the matching entries (oldest first, as JSON lines), a manifest with the verification
// result and the SHA-256 of the data. The entries keep their chain fields, so the recipient can re-verify them.
func (l *Log) Export(w io.Writer, f Filter, by string, key []byte) (Manifest, error) {
	rep, err := l.Verify(key)
	if err != nil {
		return Manifest{}, err
	}
	f.Limit = 20000
	ents, err := l.Query(f)
	if err != nil {
		return Manifest{}, err
	}
	h := sha256.New()
	zw := zip.NewWriter(w)
	dw, err := zw.Create(l.opt.Name + "-audit.jsonl")
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{Log: l.opt.Name, ExportedAt: time.Now().UTC(), ExportedBy: by, ChainOK: rep.OK, Problem: rep.Problem, Entries: len(ents),
		Algorithm: "entry hash = SHA-256 over the entry JSON without hash/mac, prev links the entries; mac = HMAC-SHA256(hash)",
		Note:      "Self-generated evidence of the key management system. Retention periods must be set by the operator's compliance policy."}
	m.Filter = fmt.Sprintf("from=%s to=%s category=%s outcome=%s who=%s op=%s text=%s", fmtT(f.From), fmtT(f.To), f.Category, f.Outcome, f.Who, f.Op, f.Text)
	m.ChainHead = rep.LastHash
	for i := len(ents) - 1; i >= 0; i-- {
		b, _ := json.Marshal(ents[i])
		b = append(b, '\n')
		h.Write(b)
		if _, err := dw.Write(b); err != nil {
			return m, err
		}
		if m.FirstSeq == 0 {
			m.FirstSeq = ents[i].Seq
		}
		m.LastSeq = ents[i].Seq
	}
	m.DataSHA256 = hex.EncodeToString(h.Sum(nil))
	mw, err := zw.Create("manifest.json")
	if err != nil {
		return m, err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if _, err := mw.Write(b); err != nil {
		return m, err
	}
	return m, zw.Close()
}

func fmtT(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// VerifyEntries checks the chain of exported entries (oldest first) the way a recipient would.
func VerifyEntries(ents []Entry, key []byte) error {
	for i, e := range ents {
		if hashOf(e) != e.Hash {
			return fmt.Errorf("entry %d modified", e.Seq)
		}
		if len(key) > 0 {
			want, _ := hex.DecodeString(macOf(key, e.Hash))
			got, _ := hex.DecodeString(e.MAC)
			if !hmac.Equal(want, got) {
				return fmt.Errorf("entry %d: bad MAC", e.Seq)
			}
		}
		if i > 0 && (e.Prev != ents[i-1].Hash || e.Seq != ents[i-1].Seq+1) {
			return fmt.Errorf("entry %d: chain broken", e.Seq)
		}
	}
	return nil
}
