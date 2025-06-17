package ginhelmet

import (
	"github.com/danielkov/gin-helmet/core"
	"github.com/gin-gonic/gin"
)

// GinHeaderWriter implements core.HeaderWriter for Gin contexts
type GinHeaderWriter struct {
	ctx *gin.Context
}

func (g *GinHeaderWriter) SetHeader(key, value string) {
	g.ctx.Writer.Header().Set(key, value)
}

func (g *GinHeaderWriter) Next() {
	g.ctx.Next()
}

// wrapMiddleware converts a core.MiddlewareFunc to gin.HandlerFunc
func wrapMiddleware(middleware core.MiddlewareFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		writer := &GinHeaderWriter{ctx: c}
		middleware(writer)
	}
}

// wrapMultipleMiddleware converts multiple core.MiddlewareFunc to multiple gin.HandlerFunc
func wrapMultipleMiddleware(middlewares []core.MiddlewareFunc) []gin.HandlerFunc {
	result := make([]gin.HandlerFunc, len(middlewares))
	for i, mw := range middlewares {
		result[i] = wrapMiddleware(mw)
	}
	return result
}

// NoRobotIndex applies header to protect your server from robot indexation
func NoRobotIndex() gin.HandlerFunc {
	return wrapMiddleware(core.NoRobotIndex())
}

// NoSniff applies header to protect your server from MimeType Sniffing
func NoSniff() gin.HandlerFunc {
	return wrapMiddleware(core.NoSniff())
}

// DNSPrefetchControl sets Prefetch Control header to prevent browser from prefetching DNS
func DNSPrefetchControl() gin.HandlerFunc {
	return wrapMiddleware(core.DNSPrefetchControl())
}

// FrameGuard sets Frame Options header to deny to prevent content from the website to be served in an iframe
func FrameGuard(opt ...string) gin.HandlerFunc {
	return wrapMiddleware(core.FrameGuard(opt...))
}

// SetHSTS Sets Strict Transport Security header to the default of 60 days
// an optional integer may be added as a parameter to set the amount in seconds
func SetHSTS(sub bool, opt ...int) gin.HandlerFunc {
	return wrapMiddleware(core.SetHSTS(sub, opt...))
}

// IENoOpen sets Download Options header for Internet Explorer to prevent it from executing downloads in the site's context
func IENoOpen() gin.HandlerFunc {
	return wrapMiddleware(core.IENoOpen())
}

// XSSFilter applies very minimal XSS protection via setting the XSS Protection header on
// NOTE: X-XSS-Protection is deprecated. Use Content Security Policy instead.
func XSSFilter() gin.HandlerFunc {
	return wrapMiddleware(core.XSSFilter())
}

// Default returns a number of handlers that are advised to use for basic HTTP(s) protection
func Default() (gin.HandlerFunc, gin.HandlerFunc, gin.HandlerFunc, gin.HandlerFunc, gin.HandlerFunc, gin.HandlerFunc) {
	middlewares := wrapMultipleMiddleware(core.Default())
	return middlewares[0], middlewares[1], middlewares[2], middlewares[3], middlewares[4], middlewares[5]
}

// Referrer sets the Referrer Policy header to prevent the browser from sending data from your website to another one upon navigation
// an optional string can be provided to set the policy to something else other than "strict-origin-when-cross-origin".
func Referrer(opt ...string) gin.HandlerFunc {
	return wrapMiddleware(core.Referrer(opt...))
}

// NoCache obliterates cache options by setting a number of headers. This prevents the browser from storing your assets in cache
func NoCache() gin.HandlerFunc {
	return wrapMiddleware(core.NoCache())
}

// ContentSecurityPolicy sets a header which will restrict your browser to only allow certain sources for assets on your website
// The function accepts a map of its parameters which are appended to the header so you can control which headers should be set
// The second parameter of the function is a boolean, which set to true will tell the handler to also set legacy headers, like
// those that work in older versions of Chrome and Firefox.
/*
Example usage:
	s.Use(ginhelmet.ContentSecurityPolicy(
		ginhelmet.CSP("default-src", "'self'"),
		ginhelmet.CSP("img-src", "*"),
		ginhelmet.CSP("media-src", "media1.com media2.com"),
		ginhelmet.CSP("script-src", "userscripts.example.com"),
	))

See [Content Security Policy on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) for more info.
*/
func ContentSecurityPolicy(opts ...string) gin.HandlerFunc {
	return wrapMiddleware(core.ContentSecurityPolicy(opts...))
}

func CSP(key, value string) string {
	return core.CSP(key, value)
}

func ContentSecurityPolicyLegacy(opts ...string) gin.HandlerFunc {
	return wrapMiddleware(core.ContentSecurityPolicyLegacy(opts...))
}

// ExpectCT sets Certificate Transparency header which can enforce that you're using a Certificate which is ready for the
// upcoming Chrome requirements policy. The function accepts a maxAge int which is the TTL for the policy in delta seconds,
// an enforce boolean, which simply adds an enforce directive to the policy (otherwise it's report-only mode) and a
// optional reportUri, which is the URI to which report information is sent when the policy is violated.
// NOTE: Expect-CT is deprecated as of June 2021.
func ExpectCT(maxAge int, enforce bool, reportURI ...string) gin.HandlerFunc {
	return wrapMiddleware(core.ExpectCT(maxAge, enforce, reportURI...))
}

// SetHPKP sets HTTP Public Key Pinning for your server. It is not necessarily a great thing to set this without proper
// knowledge of what this does. [Read here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning) otherwise you
// may likely end up DoS-ing your own server and domain. The function accepts a map of directives and their values according
// to specifications.
// NOTE: HPKP is deprecated and not recommended for use.
/*
Example usage:

	keys := []string{"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=", "M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="}
	r := gin.New()
	r.Use(ginhelmet.SetHPKP(keys, 5184000, true, "domain.com"))

*/
func SetHPKP(keys []string, maxAge int, sub bool, reportURI ...string) gin.HandlerFunc {
	return wrapMiddleware(core.SetHPKP(keys, maxAge, sub, reportURI...))
}

// CrossOriginOpenerPolicy (COOP) helps isolate your document from other origins
func CrossOriginOpenerPolicy(opt ...string) gin.HandlerFunc {
	return wrapMiddleware(core.CrossOriginOpenerPolicy(opt...))
}

// CrossOriginEmbedderPolicy (COEP) helps isolate your document from other origins
func CrossOriginEmbedderPolicy(opt ...string) gin.HandlerFunc {
	return wrapMiddleware(core.CrossOriginEmbedderPolicy(opt...))
}

// CrossOriginResourcePolicy (CORP) helps isolate your document from other origins
func CrossOriginResourcePolicy(opt ...string) gin.HandlerFunc {
	return wrapMiddleware(core.CrossOriginResourcePolicy(opt...))
}

// PermissionsPolicy sets the Permissions Policy header to control which browser features can be used
func PermissionsPolicy(policy string) gin.HandlerFunc {
	return wrapMiddleware(core.PermissionsPolicy(policy))
}

// ClearSiteData clears specific types of data from the browser
func ClearSiteData(types ...string) gin.HandlerFunc {
	return wrapMiddleware(core.ClearSiteData(types...))
}
