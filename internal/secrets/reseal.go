package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// ReEncrypter re-encrypts a SealedSecret under the controller's newest key
// (kubeseal.Sealer.ReEncrypt in production).
type ReEncrypter func(sealed []byte) ([]byte, error)

// sealedIdentity is what a re-encrypt must leave unchanged: the object's name
// and namespace and its key set. Only the ciphertext may differ.
type sealedIdentity struct {
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		EncryptedData map[string]string `yaml:"encryptedData"`
	} `yaml:"spec"`
}

func identityOf(data []byte) (string, error) {
	var s sealedIdentity
	if err := yaml.Unmarshal(data, &s); err != nil {
		return "", err
	}
	if len(s.Spec.EncryptedData) == 0 {
		return "", fmt.Errorf("no encryptedData")
	}
	keys := make([]string, 0, len(s.Spec.EncryptedData))
	for k := range s.Spec.EncryptedData {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return s.Metadata.Namespace + "/" + s.Metadata.Name + ":" + strings.Join(keys, ","), nil
}

// ResealFile re-encrypts one sealed-secret file in place. The values stay the
// same; only the ciphertext moves to the newest sealing key. The file is
// replaced only when the result has the same name, namespace and key set, and
// the replacement is atomic (temp file plus rename, mode 0600).
func ResealFile(path string, reEncrypt ReEncrypter) error {
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	before, err := identityOf(old)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	fresh, err := reEncrypt(old)
	if err != nil {
		return err
	}
	after, err := identityOf(fresh)
	if err != nil {
		return fmt.Errorf("parsing the re-encrypted %s: %w", path, err)
	}
	if after != before {
		return fmt.Errorf("re-encrypted %s changed identity (%s -> %s); file left as is", path, before, after)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".reseal-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(fresh); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
