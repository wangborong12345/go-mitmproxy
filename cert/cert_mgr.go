package cert

import (
	"crypto/x509"
	"errors"
)

var UnsupportedSystemError = errors.New("unsupported system")

type SystemTrustCertMgr interface {

	// Install add certificate to system trust list
	// will not repeat install
	Install(cert *x509.Certificate) error

	// List return all system trust certificates
	List() (*[]*x509.Certificate, error)

	// Uninstall remove certificate from system trust list
	// not found return nil
	Uninstall(cert *x509.Certificate) error
}
