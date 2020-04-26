package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

var b64 = base64.StdEncoding

type Secret struct {
	// Value is the AES-GCM encrypted text appended to the random nonce. It
	// is base64 encoded.
	Value []byte `json:"value"`

	// Users maps usernames to encrypted passwords which, when decrypted
	// using RSA, are used to decrypt the Value.
	Users map[username][]byte `json:"users"`
}

// shhV1 describes the .shh file containing secrets and public keys.
type shhV1 struct {
	// Secrets maps secretName -> (secretValue, Users). Secret names and
	// values are shared project-wide, so there can only be one instance of
	// any secret, the AES key for which is encrypted for each user using
	// their respective RSA public keys.
	Secrets map[string]*Secret `json:"secrets"`

	// Keys are RSA public keys used to encrypt secrets for each user.
	Keys map[username]*pem.Block `json:"keys"`

	// Version of the shh file. Note that this is independent of the shh
	// binary's version.
	Version int `json:"version"`

	// path of the .shh file itself.
	path string
}

// shhV0 describes the legacy .shh file format containing secrets and public
// keys. This format was abandoned because:
//
// 1. There's a security vulnerability in that AES secrets are not
//    authenticated, which allows for padded-oracle attacks.
// 2. Data was needlessly duplicated in the data structure, then deduplicated
//    at runtime. As a result of this change, `namespace` is no longer needed
//    in shhV1.
// 3. The new structure allows for a much cleaner API to interact with the
//    data, deduplicating encryption/decryption logic and simplifying the code
//    throughout.
type shhV0 struct {
	// Secrets maps users -> secret_labels -> secret_value. Each secret is
	// uniquely encrypted for each user given their public key.
	Secrets map[username]map[string]aesSecret `json:"secrets"`

	// Keys are public keys used to encrypt secrets for each user.
	Keys map[username]*pem.Block `json:"keys"`

	// namespace to which all secret names are added. This prevents two
	// users creating their own secrets which have the same name but
	// resolve to different secrets.
	namespace map[string]struct{}

	// path of the .shh file itself.
	path string
}

type aesSecret struct {
	AESKey    string `json:"key"`
	Encrypted string `json:"value"`
}

func newShh(path string) *shhV1 {
	return &shhV1{
		Secrets: map[string]*Secret{},
		Keys:    map[username]*pem.Block{},
		Version: 1,
		path:    path,
	}
}

// findFileRecursive checks for a file recursively up the filesystem until it
// hits an error.
func findFileRecursive(pth string) (string, error) {
	abs, err := filepath.Abs(pth)
	if err != nil {
		return "", fmt.Errorf("abs: %w", err)
	}
	if abs == string(filepath.Separator)+filepath.Base(pth) {
		// We hit the root, we're done
		return "", os.ErrNotExist
	}
	_, err = os.Stat(pth)
	switch {
	case os.IsNotExist(err):
		return findFileRecursive(filepath.Join("..", pth))
	case err != nil:
		return "", fmt.Errorf("stat: %w", err)
	}
	return pth, nil
}

func shhFromPath(pth string) (*shhV1, error) {
	recursivePath, err := findFileRecursive(pth)
	switch {
	case err == os.ErrNotExist:
		err = nil // Ignore error, keep going
	case err != nil:
		return nil, err
	}
	if recursivePath != "" {
		pth = recursivePath
	}
	flags := os.O_CREATE | os.O_RDWR
	fi, err := os.OpenFile(pth, flags, 0644)
	if err != nil {
		return nil, err
	}
	defer fi.Close()
	shh := newShh(pth)
	dec := json.NewDecoder(fi)
	err = dec.Decode(shh)
	switch {
	case err == io.EOF:
		// We newly created the file. Not an error, just an empty .shh
		return shh, nil
	case err != nil:
		return nil, fmt.Errorf("decode: %w", err)
	}
	return shh, nil
}

func (s *shhV1) EncodeToFile() error {
	flags := os.O_TRUNC | os.O_CREATE | os.O_WRONLY
	fi, err := os.OpenFile(s.path, flags, 0644)
	if err != nil {
		return err
	}
	defer fi.Close()
	return s.Encode(fi)
}

func (s *shhV1) Encode(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	return enc.Encode(s)
}

// decrypt a secret returning plaintext.
func (s *Secret) decrypt(
	u username,
	privKey *rsa.PrivateKey,
) (string, error) {
	// Ensure we check that the user has access to the file in the first
	// place
	base64AESEncKey, ok := s.Users[u]
	if !ok {
		return "", errors.New("no access")
	}

	tmp, err := b64.DecodeString(string(base64AESEncKey))
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	aesEncKey := []byte(tmp)

	// Decrypt the user's private id_rsa key with the provided password,
	// then use the RSA private key to decrypt the AES password.
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey,
		aesEncKey, nil)
	if err != nil {
		return "", fmt.Errorf("oaep: %w", err)
	}

	// Decrypt the secret Value using the AES password with GCM, which
	// offers Authenticated Encryption. This follows the example in Go's
	// stdlib:
	// https://godoc.org/crypto/cipher#NewGCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext, err := b64.DecodeString(string(s.Value))
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("encrypted secret too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("aes open: %w", err)
	}
	return string(plaintext), nil
}

// encrypt for all users.
func (s *Secret) encrypt(
	plaintext string,
	pubKeys map[username]*pem.Block,
) error {
	// Generate an AES key to encrypt the data. We use AES-256 which
	// requires a 32-byte key. We make a new key each time we encrypt
	// secrets to remove the risk of a nonce collision. This AES code
	// follows the example in Go's stdlib:
	//
	// https://godoc.org/crypto/cipher#NewGCM
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)
	s.Value = []byte(b64.EncodeToString(append(nonce, ciphertext...)))

	// Reencrypt the AES key for each user using their own RSA key. We use
	// OAEP per the recommendation of the Go stdlib docs:
	//
	//	The original specification for encryption and signatures with
	//	RSA is PKCS#1 and the terms "RSA encryption" and "RSA
	//	signatures" by default refer to PKCS#1 version 1.5. However,
	//	that specification has flaws and new designs should use version
	//	two, usually called by just OAEP and PSS, where possible.
	//
	// https://golang.org/pkg/crypto/rsa/
	for u := range s.Users {
		// Encrypt the AES key using the public key
		pubKey, err := x509.ParsePKCS1PublicKey(pubKeys[u].Bytes)
		if err != nil {
			return fmt.Errorf("parse public key: %w", err)
		}
		encAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
			pubKey, key, nil)
		if err != nil {
			return fmt.Errorf("oaep: %w", err)
		}
		s.Users[u] = []byte(b64.EncodeToString(encAESKey))
	}
	return nil
}

// secretsForGlob returns all secret names which match a glob pattern in O(n).
func (s *shhV1) secretsForGlob(globPattern string) []*Secret {
	var secrets []*Secret
	for secretName, secret := range s.Secrets {
		if glob(globPattern, secretName) {
			secrets = append(secrets, secret)
		}
	}
	return secrets
}

// migrateShh from any previous versions to the lastest version.
func migrateShh(filename string) error {
	byt, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	data := map[string]interface{}{}
	if err := json.Unmarshal(byt, &data); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	val, ok := data["version"]
	if !ok {
		// Default to version 0
		val = float64(0)
	}
	fltVersion, ok := val.(float64)
	if !ok {
		return errors.New("bad version")
	}
	switch fltVersion {
	case 0:
		if err = migrateShhV0(filename, byt); err != nil {
			return fmt.Errorf("migrate v0: %w", err)
		}
		return nil
	case 1:
		// This is the current version. Nothing to do.
		return nil
	default:
		return errors.New("unknown version")
	}
}

// migrateShhV0 to v1. This is a one-time migration that moves from AES-CFB to
// AES-GCM (preventing Oracle Padding Attacks) and improves the data-structure
// of the underlying file to reduce filesize and improve performance of the
// most common shh operations.
func migrateShhV0(filename string, byt []byte) error {
	fmt.Println("performing a one-time migration of .shh from v0 to v1")
	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}
	self, err := getUser(conf)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	self.Password, err = requestPassword(self.Port, defaultPasswordPrompt)
	if err != nil {
		return err
	}
	self.Keys, err = getKeys(global, self.Password)
	if err != nil {
		return err
	}

	fi, err := os.Open(filename)
	if err != nil {
		return err
	}

	shhOld := &shhV0{}
	if json.NewDecoder(fi).Decode(shhOld); err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	shhNew := &shhV1{
		Keys:    shhOld.Keys,
		Secrets: map[string]*Secret{},
		Version: 1,
		path:    filename,
	}

	// Report an error if the user running the migration doesn't have
	// access to every secret, since we're unable to convert the old
	// per-user encrypted form to the new, project-wide data structure.
	var secretCount int
	for _, oldSecrets := range shhOld.Secrets {
		if len(oldSecrets) > secretCount {
			secretCount = len(oldSecrets)
		}
	}
	if len(shhOld.Secrets[self.Username]) != secretCount {
		return errors.New("you do not have access to every secret, " +
			"so shh cannot perform a one-time security " +
			"migration automatically. ask for access (or " +
			"delete secrets to which you do not have access), " +
			"then re-run")
	}

	// Remap secrets from the old form to the new form:
	//
	// shhOld.Secrets map[username]map[secretName]aesSecret
	// to
	// shhNew.Secrets map[secretName]*Secret
	for secretName, aesSecret := range shhOld.Secrets[self.Username] {
		if _, ok := shhNew.Secrets[secretName]; !ok {
			shhNew.Secrets[secretName] = &Secret{
				Users: map[username][]byte{},
			}
		}
		for user, userSecrets := range shhOld.Secrets {
			if _, ok := userSecrets[secretName]; !ok {
				continue
			}
			shhNew.Secrets[secretName].Users[user] = []byte{}
		}

		// Decrypt the user-specific version using the AES key
		encAESKey, err := b64.DecodeString(string(aesSecret.AESKey))
		if err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader,
			self.Keys.PrivateKey, []byte(encAESKey), nil)
		if err != nil {
			return fmt.Errorf("decrypt secret: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		aesEncSecret, err := b64.DecodeString(
			string(aesSecret.Encrypted))
		if err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		ciphertext := []byte(aesEncSecret)
		iv := ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]
		stream := cipher.NewCFBDecrypter(block, iv)
		plaintext := make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, ciphertext)

		// ciphertext now contains the plaintext, since it was
		// decrypted in place.
		err = shhNew.Secrets[secretName].encrypt(string(plaintext),
			shhNew.Keys)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
	}

	if err = shhNew.EncodeToFile(); err != nil {
		return err
	}
	fmt.Println("done")
	return nil
}
