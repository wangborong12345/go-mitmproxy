//go:build !windows
// +build !windows

package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	SystemTrustFilename string

	SystemTrustCommand []string

	SystemTrustPath string

	SystemCertificateSuffix string
)

func init() {
	if pathExists("/etc/pki/ca-trust/source/anchors/") {
		SystemTrustPath = "/etc/pki/ca-trust/source/anchors/"
		SystemTrustCommand = []string{"update-ca-trust", "extract"}
	} else if pathExists("/usr/local/share/ca-certificates/") {
		SystemTrustPath = "/usr/local/share/ca-certificates/"
		SystemTrustCommand = []string{"update-ca-certificates"}
	} else if pathExists("/etc/ca-certificates/trust-source/anchors/") {
		SystemTrustPath = "/etc/ca-certificates/trust-source/anchors/"
		SystemTrustCommand = []string{"trust", "extract-compat"}
	}
	if SystemTrustCommand != nil {
		_, err := exec.LookPath(SystemTrustCommand[0])
		if err != nil {
			SystemTrustCommand = nil
		}
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func CommandWithSudo(cmd ...string) *exec.Cmd {
	if _, err := exec.LookPath("sudo"); err != nil {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("sudo", append([]string{"--"}, cmd...)...)
}

func AddInstallList(ca x509.Certificate) error {
	certificates, err := LoadSystemRoots()

	for _, certificate := range certificates {
		if certificate.IsCA && bytes.Compare(certificate.Raw, ca.Raw) == 0 {
			return nil
		}
	}
	path := filepath.Join(SystemTrustPath, CaCertCerFile)
	file, err := os.Create(path)
	if err != nil {
		log.Error(err)
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err != nil {
		log.Error(err)
		return err
	}

	cmd := CommandWithSudo(SystemTrustCommand...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(err, string(out))
		return err
	}
	return nil
}

func LoadSystemRoots() ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	dir, err := os.ReadDir(SystemTrustPath)
	if err != nil {
		log.Error(err)
		return certificates, err
	}
	for _, f := range dir {
		if f.IsDir() {
			continue
		}
		path := filepath.Join(SystemTrustPath, f.Name())
		file, err := os.ReadFile(path)
		if err != nil {
			log.Error(err)
			continue
		}
		certDERBlock, _ := pem.Decode(file)
		if certDERBlock == nil {
			return nil, fmt.Errorf("%s 中不存在 CERTIFICATE", path)
		}
		x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)
		if err != nil {
			log.Error(err)
			continue
		}
		certificates = append(certificates, x509Cert)
	}
	return certificates, nil
}
