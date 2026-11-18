package gate

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tang "github.com/anatol/tang.go"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// thumbprintHashes are the hashes clevis may use for thp/kid (tang's S1…S512).
var thumbprintHashes = []crypto.Hash{
	crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512,
}

// tangKeys is one client's Tang key set plus the thumbprint indexes tang.go
// keeps private.
type tangKeys struct {
	set *tang.KeySet
	// exchange holds every thumbprint of every derive (ECMR) key, so /rec can
	// tell an unknown kid (404) from a malformed body (400).
	exchange map[string]bool
	// signing is the S256 thumbprint of each advertised signing key: the thp
	// to pin in clevis.
	signing []string
}

// loadOrCreateKeys reads dir/*.jwk (dot-prefixed files are unadvertised, as
// in tangd). An empty or missing dir gets a fresh signing and exchange key.
func loadOrCreateKeys(dir string) (*tangKeys, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create keys dir: %w", err)
	}
	files, err := keyFiles(dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		if err := generateKeys(dir); err != nil {
			return nil, err
		}
		if files, err = keyFiles(dir); err != nil {
			return nil, err
		}
	}

	keys := &tangKeys{set: tang.NewKeySet(), exchange: map[string]bool{}}
	for _, file := range files {
		advertised := !strings.HasPrefix(filepath.Base(file), ".")
		if err := keys.add(file, advertised); err != nil {
			return nil, fmt.Errorf("key %s: %w", file, err)
		}
	}
	if err := keys.set.RecomputeAdvertisements(); err != nil {
		return nil, fmt.Errorf("keys in %s: %w", dir, err)
	}
	return keys, nil
}

func keyFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read keys dir: %w", err)
	}
	var files []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".jwk") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	return files, nil
}

func (k *tangKeys) add(file string, advertised bool) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	key, err := jwk.ParseKey(raw)
	if err != nil {
		return err
	}
	if err := k.set.AppendKey(key, advertised); err != nil {
		return err
	}
	ops, _ := key.KeyOps()
	for _, op := range ops {
		switch op {
		case jwk.KeyOpDeriveKey:
			for _, h := range thumbprintHashes {
				thp, err := key.Thumbprint(h)
				if err != nil {
					return err
				}
				k.exchange[base64.RawURLEncoding.EncodeToString(thp)] = true
			}
		case jwk.KeyOpSign:
			if advertised {
				thp, err := key.Thumbprint(crypto.SHA256)
				if err != nil {
					return err
				}
				k.signing = append(k.signing, base64.RawURLEncoding.EncodeToString(thp))
			}
		}
	}
	return nil
}

// generateKeys writes one signing and one exchange key, named by a random
// suffix, with mode 0400.
func generateKeys(dir string) error {
	sig, err := tang.GenerateVerifyKey()
	if err != nil {
		return err
	}
	exc, err := tang.GenerateExchangeKey()
	if err != nil {
		return err
	}
	for _, key := range []jwk.Key{sig, exc} {
		data, err := json.Marshal(key)
		if err != nil {
			return err
		}
		suffix := make([]byte, 8)
		if _, err := rand.Read(suffix); err != nil {
			return err
		}
		path := filepath.Join(dir, hex.EncodeToString(suffix)+".jwk")
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
		if err != nil {
			return err
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return errors.Join(werr, os.Remove(path))
		}
	}
	return nil
}
