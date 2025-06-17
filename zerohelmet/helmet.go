package zerohelmet

import (
	"net/http"

	"github.com/danielkov/gin-helmet/core"
	"github.com/zeromicro/go-zero/rest"
)

// ZeroHeaderWriter implements core.HeaderWriter for Go-Zero contexts
type ZeroHeaderWriter struct {
	writer http.ResponseWriter
}

func (z *ZeroHeaderWriter) SetHeader(key, value string) {
	z.writer.Header().Set(key, value)
}

func (z *ZeroHeaderWriter) Next() {
	// Go-Zero middleware continue automatically
}

// wrapMiddleware converts a core.MiddlewareFunc to rest.Middleware
func wrapMiddleware(middleware core.MiddlewareFunc) rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			writer := &ZeroHeaderWriter{writer: w}
			middleware(writer)
			next(w, r)
		}
	}
}

// NoRobotIndex applies header to protect your server from robot indexation
func NoRobotIndex() rest.Middleware {
	return wrapMiddleware(core.NoRobotIndex())
}

// NoSniff applies header to protect your server from MimeType Sniffing
func NoSniff() rest.Middleware {
	return wrapMiddleware(core.NoSniff())
}

// DNSPrefetchControl sets Prefetch Control header to prevent browser from prefetching DNS
func DNSPrefetchControl() rest.Middleware {
	return wrapMiddleware(core.DNSPrefetchControl())
}

// FrameGuard sets Frame Options header to deny to prevent content from the website to be served in an iframe
func FrameGuard(opt ...string) rest.Middleware {
	return wrapMiddleware(core.FrameGuard(opt...))
}

// SetHSTS Sets Strict Transport Security header to the default of 60 days
// an optional integer may be added as a parameter to set the amount in seconds
func SetHSTS(sub bool, opt ...int) rest.Middleware {
	return wrapMiddleware(core.SetHSTS(sub, opt...))
}

// IENoOpen sets Download Options header for Internet Explorer to prevent it from executing downloads in the site's context
func IENoOpen() rest.Middleware {
	return wrapMiddleware(core.IENoOpen())
}

// XSSFilter applies very minimal XSS protection via setting the XSS Protection header on
// NOTE: X-XSS-Protection is deprecated. Use Content Security Policy instead.
func XSSFilter() rest.Middleware {
	return wrapMiddleware(core.XSSFilter())
}

// Default returns middleware functions that are advised to use for basic HTTP(s) protection
func Default() []rest.Middleware {
	coreMiddlewares := core.Default()
	result := make([]rest.Middleware, len(coreMiddlewares))
	for i, mw := range coreMiddlewares {
		result[i] = wrapMiddleware(mw)
	}
	return result
}

// Referrer sets the Referrer Policy header to prevent the browser from sending data from your website to another one upon navigation
// an optional string can be provided to set the policy to something else other than "strict-origin-when-cross-origin".
func Referrer(opt ...string) rest.Middleware {
	return wrapMiddleware(core.Referrer(opt...))
}

// NoCache obliterates cache options by setting a number of headers. This prevents the browser from storing your assets in cache
func NoCache() rest.Middleware {
	return wrapMiddleware(core.NoCache())
}

// ContentSecurityPolicy sets a header which will restrict your browser to only allow certain sources for assets on your website
/*
Example usage:
	server := rest.MustNewServer(conf)
	server.Use(zerohelmet.ContentSecurityPolicy(
		zerohelmet.CSP("default-src", "'self'"),
		zerohelmet.CSP("img-src", "*"),
		zerohelmet.CSP("media-src", "media1.com media2.com"),
		zerohelmet.CSP("script-src", "userscripts.example.com"),
	))

See [Content Security Policy on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) for more info.
*/
func ContentSecurityPolicy(opts ...string) rest.Middleware {
	return wrapMiddleware(core.ContentSecurityPolicy(opts...))
}

func CSP(key, value string) string {
	return core.CSP(key, value)
}

func ContentSecurityPolicyLegacy(opts ...string) rest.Middleware {
	return wrapMiddleware(core.ContentSecurityPolicyLegacy(opts...))
}

// ExpectCT sets Certificate Transparency header which can enforce that you're using a Certificate which is ready for the
// upcoming Chrome requirements policy. The function accepts a maxAge int which is the TTL for the policy in delta seconds,
// an enforce boolean, which simply adds an enforce directive to the policy (otherwise it's report-only mode) and a
// optional reportUri, which is the URI to which report information is sent when the policy is violated.
// NOTE: Expect-CT is deprecated as of June 2021.
func ExpectCT(maxAge int, enforce bool, reportURI ...string) rest.Middleware {
	return wrapMiddleware(core.ExpectCT(maxAge, enforce, reportURI...))
}

// SetHPKP sets HTTP Public Key Pinning for your server. It is not necessarily a great thing to set this without proper
// knowledge of what this does. [Read here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning) otherwise you
// may likely end up DoS-ing your own server and domain. The function accepts a map of directives and their values according
// to specifications.
// NOTE: HPKP is deprecated and not recommended for use.
func SetHPKP(keys []string, maxAge int, sub bool, reportURI ...string) rest.Middleware {
	return wrapMiddleware(core.SetHPKP(keys, maxAge, sub, reportURI...))
}

// CrossOriginOpenerPolicy (COOP) helps isolate your document from other origins
func CrossOriginOpenerPolicy(opt ...string) rest.Middleware {
	return wrapMiddleware(core.CrossOriginOpenerPolicy(opt...))
}

// CrossOriginEmbedderPolicy (COEP) helps isolate your document from other origins
func CrossOriginEmbedderPolicy(opt ...string) rest.Middleware {
	return wrapMiddleware(core.CrossOriginEmbedderPolicy(opt...))
}

// CrossOriginResourcePolicy (CORP) helps isolate your document from other origins
func CrossOriginResourcePolicy(opt ...string) rest.Middleware {
	return wrapMiddleware(core.CrossOriginResourcePolicy(opt...))
}

// PermissionsPolicy sets the Permissions Policy header to control which browser features can be used
func PermissionsPolicy(policy string) rest.Middleware {
	return wrapMiddleware(core.PermissionsPolicy(policy))
}

// ClearSiteData clears specific types of data from the browser
func ClearSiteData(types ...string) rest.Middleware {
	return wrapMiddleware(core.ClearSiteData(types...))
}
