package aha

import (
	"crypto/md5"
	"encoding/hex"
	"net/url"
	"strings"
)

// Parameter preserves the client's wire order. Never sort parameters for signing.
type Parameter struct{ Key, Value string }

func encodeValue(value string) string {
	return strings.NewReplacer("%3A", ":", "%24", "$", "%5B", "[", "%5D", "]", "%2C", ",").Replace(url.QueryEscape(value))
}

func EncodeParameters(parameters []Parameter) string {
	var b strings.Builder
	for i, p := range parameters {
		if i != 0 {
			b.WriteByte('&')
		}
		b.WriteString(encodeValue(p.Key))
		b.WriteByte('=')
		b.WriteString(encodeValue(p.Value))
	}
	return b.String()
}

// SignControl signs the complete endpoint URL and ordered parameters, including
// the caller-provided timestamp. Credentials are supplied by the caller only.
func SignControl(endpoint string, parameters []Parameter) string {
	text := endpoint + "?" + EncodeParameters(parameters)
	// Replace '&' first: the ampersand introduced by replacing '2' must survive.
	text = strings.ReplaceAll(text, "&", "-")
	text = strings.NewReplacer("0", "~", "1", "!", "2", "&", "3", "^", "4", "$", "5", "#", "6", "%", "7", "@", "8", "*", "9", "=").Replace(text)
	sum := md5.Sum([]byte(text))
	return hex.EncodeToString(sum[:])
}
