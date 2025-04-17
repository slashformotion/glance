package glance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"html/template"
	"time"
)

var certificatesWidgetTemplate = mustParseTemplate("certificates.html", "widget-base.html")

type certificatesWidget struct {
	widgetBase `yaml:",inline"`

	Domains []certificatesDomains   `yaml:"domains"`
	Items   []certificateScanResult `yaml:"-"`
}
type certificatesDomains struct {
	HostPort string `yaml:"hostport"`
	Name     string `yaml:"name"`
}

func (widget *certificatesWidget) initialize() error {
	widget.withTitle("Certificates").withCacheDuration(1 * time.Hour)

	return nil
}

func (widget *certificatesWidget) update(ctx context.Context) {
	var err error
	res := fetchCertificatesResults(widget.Domains)
	if !widget.canContinueUpdateAfterHandlingErr(err) {
		return
	}

	widget.Items = res
}

func (widget *certificatesWidget) Render() template.HTML {
	return widget.renderTemplate(widget, certificatesWidgetTemplate)
}

type certificateScanResult struct {
	Source       certificatesDomains
	valid        bool
	certError    certError
	timeToExpiry time.Duration
}

type certError string

const (
	certErrorNotBefore = "NOT YET VALID"
	certErrorExpired   = "EXPIRED"
)

func fetchCertificatesResults(c []certificatesDomains) []certificateScanResult {
	res := make([]certificateScanResult, 0)
	for _, d := range c {
		s, err := fetchCertificatesResult(d)
		if err != nil {
			continue
		}

		res = append(res, s)
	}

	return res
}

var errNoCerts = errors.New("no certs")

func fetchCertificatesResult(c certificatesDomains) (certificateScanResult, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", "www.google.com:443", conf)
	if err != nil {
		return certificateScanResult{}, nil
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return certificateScanResult{}, errNoCerts
	}
	return mappingCert(*certs[0], c), nil
}

func mappingCert(c x509.Certificate, source certificatesDomains) certificateScanResult {
	r := certificateScanResult{
		Source: source,
		valid:  true,
	}
	n := time.Now()

	if n.Before(c.NotBefore) {
		r.valid = false
		r.certError = certErrorNotBefore
	} else if n.After(c.NotAfter) {
		r.valid = false
		r.certError = certErrorExpired
	} else {
		r.timeToExpiry = n.Sub(c.NotAfter)
	}

	return r
}
