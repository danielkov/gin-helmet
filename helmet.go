// Package ginhelmet provides security middleware for Gin web framework.
//
// Deprecated: This package is deprecated. Please use github.com/danielkov/gin-helmet/ginhelmet instead.
// This package is maintained for backwards compatibility only.
//
// Migration example:
//
//	Old: import "github.com/danielkov/gin-helmet"
//	New: import "github.com/danielkov/gin-helmet/ginhelmet"
//
// All function calls remain the same, just change the import path.
package ginhelmet

import (
	"github.com/danielkov/gin-helmet/ginhelmet"
	"github.com/gin-gonic/gin"
)

// NoRobotIndex applies header to protect your server from robot indexation.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.NoRobotIndex instead.
func NoRobotIndex() gin.HandlerFunc {
	return ginhelmet.NoRobotIndex()
}

// NoSniff applies header to protect your server from MimeType Sniffing.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.NoSniff instead.
func NoSniff() gin.HandlerFunc {
	return ginhelmet.NoSniff()
}

// DNSPrefetchControl sets Prefetch Control header to prevent browser from prefetching DNS.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.DNSPrefetchControl instead.
func DNSPrefetchControl() gin.HandlerFunc {
	return ginhelmet.DNSPrefetchControl()
}

// FrameGuard sets Frame Options header to deny to prevent content from the website to be served in an iframe.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.FrameGuard instead.
func FrameGuard(opt ...string) gin.HandlerFunc {
	return ginhelmet.FrameGuard(opt...)
}

// SetHSTS Sets Strict Transport Security header to the default of 60 days
// an optional integer may be added as a parameter to set the amount in seconds.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.SetHSTS instead.
func SetHSTS(sub bool, opt ...int) gin.HandlerFunc {
	return ginhelmet.SetHSTS(sub, opt...)
}

// IENoOpen sets Download Options header for Internet Explorer to prevent it from executing downloads in the site's context.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.IENoOpen instead.
func IENoOpen() gin.HandlerFunc {
	return ginhelmet.IENoOpen()
}

// XSSFilter applies very minimal XSS protection via setting the XSS Protection header on.
// NOTE: X-XSS-Protection is deprecated. Use Content Security Policy instead.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.XSSFilter instead.
func XSSFilter() gin.HandlerFunc {
	return ginhelmet.XSSFilter()
}

// Default returns a number of handlers that are advised to use for basic HTTP(s) protection.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.Default instead.
func Default() (gin.HandlerFunc, gin.HandlerFunc, gin.HandlerFunc, gin.HandlerFunc, gin.HandlerFunc, gin.HandlerFunc) {
	return ginhelmet.Default()
}

// Referrer sets the Referrer Policy header to prevent the browser from sending data from your website to another one upon navigation
// an optional string can be provided to set the policy to something else other than "strict-origin-when-cross-origin".
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.Referrer instead.
func Referrer(opt ...string) gin.HandlerFunc {
	return ginhelmet.Referrer(opt...)
}

// NoCache obliterates cache options by setting a number of headers. This prevents the browser from storing your assets in cache.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.NoCache instead.
func NoCache() gin.HandlerFunc {
	return ginhelmet.NoCache()
}

// ContentSecurityPolicy sets a header which will restrict your browser to only allow certain sources for assets on your website.
// The function accepts a map of its parameters which are appended to the header so you can control which headers should be set.
//
// Example usage:
//
//	s.Use(ginhelmet.ContentSecurityPolicy(
//		ginhelmet.CSP("default-src", "'self'"),
//		ginhelmet.CSP("img-src", "*"),
//		ginhelmet.CSP("media-src", "media1.com media2.com"),
//		ginhelmet.CSP("script-src", "userscripts.example.com"),
//	))
//
// See [Content Security Policy on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) for more info.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.ContentSecurityPolicy instead.
func ContentSecurityPolicy(opts ...string) gin.HandlerFunc {
	return ginhelmet.ContentSecurityPolicy(opts...)
}

// CSP is a helper function for building Content Security Policy directives.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.CSP instead.
func CSP(key, value string) string {
	return ginhelmet.CSP(key, value)
}

// ContentSecurityPolicyLegacy sets CSP header with legacy browser support.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.ContentSecurityPolicyLegacy instead.
func ContentSecurityPolicyLegacy(opts ...string) gin.HandlerFunc {
	return ginhelmet.ContentSecurityPolicyLegacy(opts...)
}

// ExpectCT sets Certificate Transparency header which can enforce that you're using a Certificate which is ready for the
// upcoming Chrome requirements policy. The function accepts a maxAge int which is the TTL for the policy in delta seconds,
// an enforce boolean, which simply adds an enforce directive to the policy (otherwise it's report-only mode) and a
// optional reportUri, which is the URI to which report information is sent when the policy is violated.
// NOTE: Expect-CT is deprecated as of June 2021.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.ExpectCT instead.
func ExpectCT(maxAge int, enforce bool, reportURI ...string) gin.HandlerFunc {
	return ginhelmet.ExpectCT(maxAge, enforce, reportURI...)
}

// SetHPKP sets HTTP Public Key Pinning for your server. It is not necessarily a great thing to set this without proper
// knowledge of what this does. [Read here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning) otherwise you
// may likely end up DoS-ing your own server and domain. The function accepts a map of directives and their values according
// to specifications.
// NOTE: HPKP is deprecated and not recommended for use.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.SetHPKP instead.
func SetHPKP(keys []string, maxAge int, sub bool, reportURI ...string) gin.HandlerFunc {
	return ginhelmet.SetHPKP(keys, maxAge, sub, reportURI...)
}

// CrossOriginOpenerPolicy (COOP) helps isolate your document from other origins.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.CrossOriginOpenerPolicy instead.
func CrossOriginOpenerPolicy(opt ...string) gin.HandlerFunc {
	return ginhelmet.CrossOriginOpenerPolicy(opt...)
}

// CrossOriginEmbedderPolicy (COEP) helps isolate your document from other origins.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.CrossOriginEmbedderPolicy instead.
func CrossOriginEmbedderPolicy(opt ...string) gin.HandlerFunc {
	return ginhelmet.CrossOriginEmbedderPolicy(opt...)
}

// CrossOriginResourcePolicy (CORP) helps isolate your document from other origins.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.CrossOriginResourcePolicy instead.
func CrossOriginResourcePolicy(opt ...string) gin.HandlerFunc {
	return ginhelmet.CrossOriginResourcePolicy(opt...)
}

// PermissionsPolicy sets the Permissions Policy header to control which browser features can be used.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.PermissionsPolicy instead.
func PermissionsPolicy(policy string) gin.HandlerFunc {
	return ginhelmet.PermissionsPolicy(policy)
}

// ClearSiteData clears specific types of data from the browser.
//
// Deprecated: Use github.com/danielkov/gin-helmet/ginhelmet.ClearSiteData instead.
func ClearSiteData(types ...string) gin.HandlerFunc {
	return ginhelmet.ClearSiteData(types...)
}
