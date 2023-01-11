//go:build windows
// +build windows

package cert

import (
	"bytes"
	"crypto/x509"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

// AddInstallList install the ca certificate to system list
func AddInstallList(ca x509.Certificate) error {

	certificates, err := LoadSystemRoots()
	if err != nil {
		log.Error(err)
		return err
	}

	for _, certificate := range certificates {
		if certificate.IsCA && bytes.Compare(certificate.Raw, ca.Raw) == 0 {
			return nil
		}
	}

	utf16Ptr, err := syscall.UTF16PtrFromString("ROOT")
	if err != nil {
		log.Error(utf16Ptr)
		return err
	}
	store, err := syscall.CertOpenSystemStore(0, utf16Ptr)
	defer syscall.CertCloseStore(store, 0)

	if err != nil {
		log.Error(err)
		return err
	}

	var cert *syscall.CertContext
	cert, err = syscall.CertEnumCertificatesInStore(store, cert)
	if err != nil {
		panic(err)
	}

	leafCtx, err := syscall.CertCreateCertificateContext(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING, &ca.Raw[0], uint32(len(ca.Raw)))

	err = syscall.CertAddCertificateContextToStore(store, leafCtx, windows.CERT_STORE_ADD_USE_EXISTING, nil)
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

// LoadSystemRoots load system certificate list
func LoadSystemRoots() ([]*x509.Certificate, error) {
	const CryptENotFound = 0x80092004
	var certificates []*x509.Certificate
	utf16PtrFromString, err := syscall.UTF16PtrFromString("ROOT")
	if err != nil {
		log.Error(err)
		return nil, err
	}
	store, err := syscall.CertOpenSystemStore(0, utf16PtrFromString)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	defer syscall.CertCloseStore(store, 0)

	var cert *syscall.CertContext
	for {
		cert, err = syscall.CertEnumCertificatesInStore(store, cert)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == CryptENotFound {
					break
				}
			}
			log.Error(err)
			return nil, err
		}
		if cert == nil {
			break
		}

		buf := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:]
		buf2 := make([]byte, cert.Length)
		copy(buf2, buf)
		if c, err := x509.ParseCertificate(buf2); err == nil {
			certificates = append(certificates, c)
		}
	}
	return certificates, nil
}
