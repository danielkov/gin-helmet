package core

import (
	"fmt"
	"strconv"
	"strings"
)

// HeaderWriter is the interface that abstracts HTTP header writing across different frameworks
type HeaderWriter interface {
	SetHeader(key, value string)
	Next()
}

// MiddlewareFunc is a function that takes a HeaderWriter and processes it
type MiddlewareFunc func(HeaderWriter)

// NoRobotIndex applies header to protect your server from robot indexation
func NoRobotIndex() MiddlewareFunc {
	return func(w HeaderWriter) {
		w.SetHeader("X-Robots-Tag", "noindex")
		w.Next()
	}
}

// NoSniff applies header to protect your server from MimeType Sniffing
func NoSniff() MiddlewareFunc {
	return func(w HeaderWriter) {
		w.SetHeader("X-Content-Type-Options", "nosniff")
		w.Next()
	}
}

// DNSPrefetchControl sets Prefetch Control header to prevent browser from prefetching DNS
func DNSPrefetchControl() MiddlewareFunc {
	return func(w HeaderWriter) {
		w.SetHeader("X-DNS-Prefetch-Control", "off")
		w.Next()
	}
}

// FrameGuard sets Frame Options header to deny to prevent content from the website to be served in an iframe
func FrameGuard(opt ...string) MiddlewareFunc {
	var o string
	if len(opt) > 0 {
		o = opt[0]
	} else {
		o = "DENY"
	}
	return func(w HeaderWriter) {
		w.SetHeader("X-Frame-Options", o)
		w.Next()
	}
}

// SetHSTS Sets Strict Transport Security header to the default of 60 days
// an optional integer may be added as a parameter to set the amount in seconds
func SetHSTS(sub bool, opt ...int) MiddlewareFunc {
	var o int
	if len(opt) > 0 {
		o = opt[0]
	} else {
		o = 5184000
	}
	op := "max-age=" + strconv.Itoa(o)
	if sub {
		op += "; includeSubDomains"
	}
	return func(w HeaderWriter) {
		w.SetHeader("Strict-Transport-Security", op)
		w.Next()
	}
}

// IENoOpen sets Download Options header for Internet Explorer to prevent it from executing downloads in the site's context
func IENoOpen() MiddlewareFunc {
	return func(w HeaderWriter) {
		w.SetHeader("X-Download-Options", "noopen")
		w.Next()
	}
}

// XSSFilter applies very minimal XSS protection via setting the XSS Protection header on
// NOTE: X-XSS-Protection is deprecated. Use Content Security Policy instead.
func XSSFilter() MiddlewareFunc {
	return func(w HeaderWriter) {
		w.SetHeader("X-XSS-Protection", "1; mode=block")
		w.Next()
	}
}

// Default returns a slice of middleware functions that are advised to use for basic HTTP(s) protection
func Default() []MiddlewareFunc {
	return []MiddlewareFunc{
		NoSniff(),
		DNSPrefetchControl(),
		FrameGuard(),
		SetHSTS(true),
		IENoOpen(),
		XSSFilter(),
	}
}

// Referrer sets the Referrer Policy header to prevent the browser from sending data from your website to another one upon navigation
// an optional string can be provided to set the policy to something else other than "strict-origin-when-cross-origin".
func Referrer(opt ...string) MiddlewareFunc {
	var o string
	if len(opt) > 0 {
		o = opt[0]
	} else {
		o = "strict-origin-when-cross-origin"
	}
	return func(w HeaderWriter) {
		w.SetHeader("Referrer-Policy", o)
		w.Next()
	}
}

// NoCache obliterates cache options by setting a number of headers. This prevents the browser from storing your assets in cache
func NoCache() MiddlewareFunc {
	return func(w HeaderWriter) {
		w.SetHeader("Surrogate-Control", "no-store")
		w.SetHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		w.SetHeader("Pragma", "no-cache")
		w.SetHeader("Expires", "0")
		w.Next()
	}
}

// ContentSecurityPolicy sets a header which will restrict your browser to only allow certain sources for assets on your website
// The function accepts a map of its parameters which are appended to the header so you can control which headers should be set
// The second parameter of the function is a boolean, which set to true will tell the handler to also set legacy headers, like
// those that work in older versions of Chrome and Firefox.
/*
Example usage:
	helmet.ContentSecurityPolicy(
		helmet.CSP("default-src", "'self'"),
		helmet.CSP("img-src", "*"),
		helmet.CSP("media-src", "media1.com media2.com"),
		helmet.CSP("script-src", "userscripts.example.com"),
	)

See [Content Security Policy on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) for more info.
*/
func ContentSecurityPolicy(opts ...string) MiddlewareFunc {
	policy := strings.Join(opts, "; ")
	return func(w HeaderWriter) {
		w.SetHeader("Content-Security-Policy", policy)
		w.Next()
	}
}

func CSP(key, value string) string {
	return fmt.Sprintf("%s %s", key, value)
}

func ContentSecurityPolicyLegacy(opts ...string) MiddlewareFunc {
	policy := strings.Join(opts, "; ")
	return func(w HeaderWriter) {
		w.SetHeader("Content-Security-Policy", policy)
		w.SetHeader("X-Webkit-CSP", policy)
		w.SetHeader("X-Content-Security-Policy", policy)
		w.Next()
	}
}

// ExpectCT sets Certificate Transparency header which can enforce that you're using a Certificate which is ready for the
// upcoming Chrome requirements policy. The function accepts a maxAge int which is the TTL for the policy in delta seconds,
// an enforce boolean, which simply adds an enforce directive to the policy (otherwise it's report-only mode) and a
// optional reportUri, which is the URI to which report information is sent when the policy is violated.
//
// Deprecated: Expect-CT is mostly obsolete as of June 2021.
func ExpectCT(maxAge int, enforce bool, reportURI ...string) MiddlewareFunc {
	policy := ""
	if enforce {
		policy += "enforce, "
	}
	if len(reportURI) > 0 {
		policy += fmt.Sprintf("report-uri=%s, ", reportURI[0])
	}
	policy += fmt.Sprintf("max-age=%d", maxAge)
	return func(w HeaderWriter) {
		w.SetHeader("Expect-CT", policy)
		w.Next()
	}
}

// SetHPKP sets HTTP Public Key Pinning for your server. It is not necessarily a great thing to set this without proper
// knowledge of what this does. [Read here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning) otherwise you
// may likely end up DoS-ing your own server and domain. The function accepts a list of keys, a maxAge, a sub boolean, and an optional reportURI.
// NOTE: HPKP is deprecated and not recommended for use.
/*
Example usage:

	keys := []string{"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=", "M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="}
	helmet.SetHPKP(keys, 5184000, true, "domain.com")

*/
func SetHPKP(keys []string, maxAge int, sub bool, reportURI ...string) MiddlewareFunc {
	policyParts := []string{}
	for _, v := range keys {
		policyParts = append(policyParts, fmt.Sprintf("pin-sha256=\"%s\"", v))
	}
	policyParts = append(policyParts, fmt.Sprintf("max-age=%d", maxAge))
	if sub {
		policyParts = append(policyParts, "includeSubDomains")
	}
	if len(reportURI) > 0 {
		policyParts = append(policyParts, fmt.Sprintf("report-uri=\"%s\"", reportURI[0]))
	}
	policy := strings.Join(policyParts, "; ")
	return func(w HeaderWriter) {
		w.SetHeader("Public-Key-Pins", policy)
		w.Next()
	}
}

// CrossOriginOpenerPolicy (COOP) helps isolate your document from other origins
func CrossOriginOpenerPolicy(opt ...string) MiddlewareFunc {
	var o string
	if len(opt) > 0 {
		o = opt[0]
	} else {
		o = "same-origin"
	}
	return func(w HeaderWriter) {
		w.SetHeader("Cross-Origin-Opener-Policy", o)
		w.Next()
	}
}

// CrossOriginEmbedderPolicy (COEP) helps isolate your document from other origins
func CrossOriginEmbedderPolicy(opt ...string) MiddlewareFunc {
	var o string
	if len(opt) > 0 {
		o = opt[0]
	} else {
		o = "require-corp"
	}
	return func(w HeaderWriter) {
		w.SetHeader("Cross-Origin-Embedder-Policy", o)
		w.Next()
	}
}

// CrossOriginResourcePolicy (CORP) helps isolate your document from other origins
func CrossOriginResourcePolicy(opt ...string) MiddlewareFunc {
	var o string
	if len(opt) > 0 {
		o = opt[0]
	} else {
		o = "cross-origin"
	}
	return func(w HeaderWriter) {
		w.SetHeader("Cross-Origin-Resource-Policy", o)
		w.Next()
	}
}

// PermissionsPolicy sets the Permissions Policy header to control which browser features can be used
func PermissionsPolicy(policy string) MiddlewareFunc {
	return func(w HeaderWriter) {
		w.SetHeader("Permissions-Policy", policy)
		w.Next()
	}
}

// ClearSiteData clears specific types of data from the browser
func ClearSiteData(types ...string) MiddlewareFunc {
	var dataTypes []string
	if len(types) == 0 {
		dataTypes = []string{"cache", "cookies", "storage", "executionContexts"}
	} else {
		dataTypes = types
	}

	// Quote each type and join with commas
	quotedTypes := make([]string, len(dataTypes))
	for i, t := range dataTypes {
		quotedTypes[i] = fmt.Sprintf("\"%s\"", t)
	}
	value := strings.Join(quotedTypes, ", ")

	return func(w HeaderWriter) {
		w.SetHeader("Clear-Site-Data", value)
		w.Next()
	}
}
