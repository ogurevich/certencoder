// Package certencoder is a Traefik local plugin that URL-encodes the
// X-Forwarded-Tls-Client-Cert header. Traefik v3 changed the passTLSClientCert
// middleware to send the raw base64 DER value without URL-encoding, whereas
// Traefik v2 sent a URL-encoded value. Applications that call
// URLDecoder.decode() on the header value convert '+' to a space character,
// corrupting the base64 data. This plugin restores the Traefik v2 behaviour by
// percent-encoding the characters that URLDecoder.decode() would otherwise
// misinterpret: '+' -> '%2B', '/' -> '%2F', '=' -> '%3D'.
package certencoder

import (
	"context"
	"net/http"
	"strings"
)

// Config holds the plugin configuration.
type Config struct {
	HeaderName string `json:"headerName,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		HeaderName: "X-Forwarded-Tls-Client-Cert",
	}
}

// CertEncoder is the plugin handler.
type CertEncoder struct {
	next       http.Handler
	headerName string
	name       string
}

// New creates a new CertEncoder plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	headerName := config.HeaderName
	if headerName == "" {
		headerName = "X-Forwarded-Tls-Client-Cert"
	}
	return &CertEncoder{
		next:       next,
		headerName: headerName,
		name:       name,
	}, nil
}

func (c *CertEncoder) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	value := req.Header.Get(c.headerName)
	if value != "" {
		req.Header.Set(c.headerName, urlEncodeBase64(value))
	}
	c.next.ServeHTTP(rw, req)
}

// urlEncodeBase64 percent-encodes characters in a base64 string that would be
// misinterpreted by Java's URLDecoder.decode():
//   '+' (base64 char 62) -> '%2B'  – otherwise decoded as space
//   '/' (base64 char 63) -> '%2F'
//   '=' (padding)        -> '%3D'
func urlEncodeBase64(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '+':
			b.WriteString("%2B")
		case '/':
			b.WriteString("%2F")
		case '=':
			b.WriteString("%3D")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
