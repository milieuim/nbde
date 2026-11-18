package gate

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SignatureNamespace binds approval signatures to this purpose, so a
// signature made for anything else (git commits, files) never verifies here.
const SignatureNamespace = "nbde-unlock-gate@v1"

const (
	sshsigMagic   = "SSHSIG"
	sshsigVersion = 1
	armorBegin    = "-----BEGIN SSH SIGNATURE-----"
	armorEnd      = "-----END SSH SIGNATURE-----"
)

// sshsigBlob is the wire format of PROTOCOL.sshsig after the magic preamble.
type sshsigBlob struct {
	Version   uint32
	PublicKey []byte
	Namespace string
	Reserved  string
	HashAlg   string
	Signature []byte
}

// signedData is what the key actually signs.
type signedData struct {
	Namespace string
	Reserved  string
	HashAlg   string
	Hash      []byte
}

// verifySSHSig checks an armored `ssh-keygen -Y sign` signature over message
// against the allowed keys and returns the key that signed it. Security-key
// signatures are rejected without the user-presence flag (x/crypto/ssh
// enforces it in Verify).
func verifySSHSig(armored string, message []byte, allowed []ssh.PublicKey, requireSK bool) (ssh.PublicKey, error) {
	raw, err := dearmor(armored)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(raw, []byte(sshsigMagic)) {
		return nil, errors.New("sshsig: missing magic")
	}
	var blob sshsigBlob
	if err := ssh.Unmarshal(raw[len(sshsigMagic):], &blob); err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	if blob.Version != sshsigVersion {
		return nil, fmt.Errorf("sshsig: unsupported version %d", blob.Version)
	}
	if blob.Namespace != SignatureNamespace {
		return nil, fmt.Errorf("sshsig: namespace %q, want %q", blob.Namespace, SignatureNamespace)
	}
	pub, err := ssh.ParsePublicKey(blob.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sshsig: public key: %w", err)
	}
	if !keyAllowed(pub, allowed) {
		return nil, errors.New("sshsig: key is not an approver")
	}
	if requireSK && !isSecurityKey(pub) {
		return nil, errors.New("sshsig: approver key is not a security key")
	}

	var digest []byte
	switch blob.HashAlg {
	case "sha512":
		h := sha512.Sum512(message)
		digest = h[:]
	case "sha256":
		h := sha256.Sum256(message)
		digest = h[:]
	default:
		return nil, fmt.Errorf("sshsig: unsupported hash %q", blob.HashAlg)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(blob.Signature, &sig); err != nil {
		return nil, fmt.Errorf("sshsig: signature: %w", err)
	}
	data := append([]byte(sshsigMagic), ssh.Marshal(signedData{
		Namespace: blob.Namespace,
		Reserved:  blob.Reserved,
		HashAlg:   blob.HashAlg,
		Hash:      digest,
	})...)
	if err := pub.Verify(data, &sig); err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	return pub, nil
}

func keyAllowed(pub ssh.PublicKey, allowed []ssh.PublicKey) bool {
	wire := pub.Marshal()
	for _, k := range allowed {
		if bytes.Equal(k.Marshal(), wire) {
			return true
		}
	}
	return false
}

func dearmor(armored string) ([]byte, error) {
	text := strings.TrimSpace(armored)
	if !strings.HasPrefix(text, armorBegin) || !strings.HasSuffix(text, armorEnd) {
		return nil, errors.New("sshsig: not an armored SSH signature")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(text, armorBegin), armorEnd)
	body = strings.Join(strings.Fields(body), "")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	return raw, nil
}
