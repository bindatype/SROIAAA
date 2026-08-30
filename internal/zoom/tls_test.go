package zoom

import "crypto/tls"

// insecureTLS trusts the httptest server's self-signed certificate. It exists
// only in tests; New refuses a non-https URL precisely so that production
// traffic cannot take a weaker path.
func insecureTLS() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
