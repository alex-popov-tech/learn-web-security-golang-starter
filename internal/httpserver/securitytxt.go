package httpserver

import (
	"fmt"
	"net/http"
	"time"
)

// securityTxtValidity keeps Expires within RFC 9116's recommended one-year limit.
const securityTxtValidity = 180 * 24 * time.Hour

// securityTxt serves RFC 9116 contact details for vulnerability reports.
// Expires is generated per request so the file never goes stale.
func securityTxt(responseWriter http.ResponseWriter, _ *http.Request) {
	expires := time.Now().UTC().Add(securityTxtValidity).Format(time.RFC3339)
	responseWriter.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(
		responseWriter,
		"Contact: mailto:security@bearlysecure.example\n"+
			"Policy: https://bearlysecure.example/security-policy\n"+
			"Expires: %s\n",
		expires,
	)
}
