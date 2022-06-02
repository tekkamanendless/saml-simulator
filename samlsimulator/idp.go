package samlsimulator

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml"
	"github.com/sirupsen/logrus"
)

// createIDP builds a `saml.IdentityProvider` using the given seed.
//
// This uses random numbers, so as long as the seed is the same, the output will be the
// same every time.
func createIDP(r *http.Request, seed int64, ssoURL url.URL) (*saml.IdentityProvider, error) {
	var randomReader io.Reader
	{
		randomSource := rand.NewSource(seed)
		randomReader = rand.New(randomSource)
	}

	// generate key
	privatekey, err := rsa.GenerateKey(randomReader, 2048)
	if err != nil {
		return nil, fmt.Errorf("could not generate RSA key: %w", err)
	}

	notBefore := time.Date(2000, 1, 1, 0, 0, 0, 0, time.Now().UTC().Location()) // Start on January 1, 2000.  This is in the past and will always be fine.
	notAfter := time.Date(2100, 1, 1, 0, 0, 0, 0, time.Now().UTC().Location())  // End on January 1, 2100.  This is in the far future and will hopefully be fine.

	template := x509.Certificate{
		SerialNumber: big.NewInt(seed), // Use the seed as the serial number.
		Subject: pkix.Name{
			Organization: []string{"Example Dot Com"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(randomReader, &template, &template, &privatekey.PublicKey, privatekey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	c, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	serviceProviderProvider := &ServiceProviderProvider{}

	samlIDP := saml.IdentityProvider{
		Key:         privatekey,
		Logger:      logrus.StandardLogger(),
		Certificate: c,
		SSOURL:      ssoURL,
		//MetadataURL: metadataURL, // TODO
		//LogoutURL: logoutURL, // TODO
		ServiceProviderProvider: serviceProviderProvider,
	}
	return &samlIDP, nil
}

// ServiceProviderProvider is a simple saml.ServiceProviderProvider that will use an existing
// SAML request to reverse-engineer a valid service provider.
type ServiceProviderProvider struct {
	req *saml.IdpAuthnRequest // This is the SAML request.
}

// SetRequest sets the SAML request to use to reverse-engineer the metadata.
//
// If this is not set, then GetServiceProvider will fail.
func (s *ServiceProviderProvider) SetRequest(req *saml.IdpAuthnRequest) {
	s.req = req
}

// GetServiceProvider returns the Service Provider metadata for the
// service provider ID, which is typically the service provider's
// metadata URL. If an appropriate service provider cannot be found then
// the returned error must be os.ErrNotExist.
//
// This cheats by using the SAML request to reverse-engineer some valid metadata
// that exactly matches what was provided.
//
// Please ensure that your call SetRequest before using this.
func (s *ServiceProviderProvider) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	// If we don't have the request, then fail.
	if s.req == nil {
		return nil, os.ErrNotExist
	}

	// Create a minimal service provider.
	p := &saml.EntityDescriptor{
		EntityID:         "",                       // We'll fill this out later.
		SPSSODescriptors: []saml.SPSSODescriptor{}, // We'll add to this later.
		// TODO: What other fields should we fake?
	}
	if s.req.Request.Issuer != nil {
		p.EntityID = s.req.Request.Issuer.Value
	}
	if s.req.Request.AssertionConsumerServiceURL != "" {
		descriptor := saml.SPSSODescriptor{
			AssertionConsumerServices: []saml.IndexedEndpoint{
				{
					Binding:  saml.HTTPPostBinding,                      // The `saml` package only supports the POST binding.
					Location: s.req.Request.AssertionConsumerServiceURL, // Use the ACS URL.
				},
			},
			// TODO: What other fields should we fake?
		}
		p.SPSSODescriptors = append(p.SPSSODescriptors, descriptor)
	}

	return p, nil
}
