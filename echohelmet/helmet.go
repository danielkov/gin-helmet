package echohelmet

import (
	"github.com/danielkov/gin-helmet/core"
	"github.com/labstack/echo/v4"
)

// EchoHeaderWriter implements core.HeaderWriter for Echo contexts
type EchoHeaderWriter struct {
	ctx echo.Context
}

func (e *EchoHeaderWriter) SetHeader(key, value string) {
	e.ctx.Response().Header().Set(key, value)
}

func (e *EchoHeaderWriter) Next() {
	// Echo middleware automatically calls next unless error is returned
}

// wrapMiddleware converts a core.MiddlewareFunc to echo.MiddlewareFunc
func wrapMiddleware(middleware core.MiddlewareFunc) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			writer := &EchoHeaderWriter{ctx: c}
			middleware(writer)
			return next(c)
		}
	}
}

// NoRobotIndex applies header to protect your server from robot indexation
func NoRobotIndex() echo.MiddlewareFunc {
	return wrapMiddleware(core.NoRobotIndex())
}

// NoSniff applies header to protect your server from MimeType Sniffing
func NoSniff() echo.MiddlewareFunc {
	return wrapMiddleware(core.NoSniff())
}

// DNSPrefetchControl sets Prefetch Control header to prevent browser from prefetching DNS
func DNSPrefetchControl() echo.MiddlewareFunc {
	return wrapMiddleware(core.DNSPrefetchControl())
}

// FrameGuard sets Frame Options header to deny to prevent content from the website to be served in an iframe
func FrameGuard(opt ...string) echo.MiddlewareFunc {
	return wrapMiddleware(core.FrameGuard(opt...))
}

// SetHSTS Sets Strict Transport Security header to the default of 60 days
// an optional integer may be added as a parameter to set the amount in seconds
func SetHSTS(sub bool, opt ...int) echo.MiddlewareFunc {
	return wrapMiddleware(core.SetHSTS(sub, opt...))
}

// IENoOpen sets Download Options header for Internet Explorer to prevent it from executing downloads in the site's context
func IENoOpen() echo.MiddlewareFunc {
	return wrapMiddleware(core.IENoOpen())
}

// XSSFilter applies very minimal XSS protection via setting the XSS Protection header on
// NOTE: X-XSS-Protection is deprecated. Use Content Security Policy instead.
func XSSFilter() echo.MiddlewareFunc {
	return wrapMiddleware(core.XSSFilter())
}

// Default returns middleware functions that are advised to use for basic HTTP(s) protection
func Default() []echo.MiddlewareFunc {
	coreMiddlewares := core.Default()
	result := make([]echo.MiddlewareFunc, len(coreMiddlewares))
	for i, mw := range coreMiddlewares {
		result[i] = wrapMiddleware(mw)
	}
	return result
}

// Referrer sets the Referrer Policy header to prevent the browser from sending data from your website to another one upon navigation
// an optional string can be provided to set the policy to something else other than "strict-origin-when-cross-origin".
func Referrer(opt ...string) echo.MiddlewareFunc {
	return wrapMiddleware(core.Referrer(opt...))
}

// NoCache obliterates cache options by setting a number of headers. This prevents the browser from storing your assets in cache
func NoCache() echo.MiddlewareFunc {
	return wrapMiddleware(core.NoCache())
}

// ContentSecurityPolicy sets a header which will restrict your browser to only allow certain sources for assets on your website
/*
Example usage:
	e.Use(echohelmet.ContentSecurityPolicy(
		echohelmet.CSP("default-src", "'self'"),
		echohelmet.CSP("img-src", "*"),
		echohelmet.CSP("media-src", "media1.com media2.com"),
		echohelmet.CSP("script-src", "userscripts.example.com"),
	))

See [Content Security Policy on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) for more info.
*/
func ContentSecurityPolicy(opts ...string) echo.MiddlewareFunc {
	return wrapMiddleware(core.ContentSecurityPolicy(opts...))
}

func CSP(key, value string) string {
	return core.CSP(key, value)
}

func ContentSecurityPolicyLegacy(opts ...string) echo.MiddlewareFunc {
	return wrapMiddleware(core.ContentSecurityPolicyLegacy(opts...))
}

// ExpectCT sets Certificate Transparency header which can enforce that you're using a Certificate which is ready for the
// upcoming Chrome requirements policy. The function accepts a maxAge int which is the TTL for the policy in delta seconds,
// an enforce boolean, which simply adds an enforce directive to the policy (otherwise it's report-only mode) and a
// optional reportUri, which is the URI to which report information is sent when the policy is violated.
// NOTE: Expect-CT is deprecated as of June 2021.
func ExpectCT(maxAge int, enforce bool, reportURI ...string) echo.MiddlewareFunc {
	return wrapMiddleware(core.ExpectCT(maxAge, enforce, reportURI...))
}

// SetHPKP sets HTTP Public Key Pinning for your server. It is not necessarily a great thing to set this without proper
// knowledge of what this does. [Read here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning) otherwise you
// may likely end up DoS-ing your own server and domain. The function accepts a map of directives and their values according
// to specifications.
// NOTE: HPKP is deprecated and not recommended for use.
func SetHPKP(keys []string, maxAge int, sub bool, reportURI ...string) echo.MiddlewareFunc {
	return wrapMiddleware(core.SetHPKP(keys, maxAge, sub, reportURI...))
}

// CrossOriginOpenerPolicy (COOP) helps isolate your document from other origins
func CrossOriginOpenerPolicy(opt ...string) echo.MiddlewareFunc {
	return wrapMiddleware(core.CrossOriginOpenerPolicy(opt...))
}

// CrossOriginEmbedderPolicy (COEP) helps isolate your document from other origins
func CrossOriginEmbedderPolicy(opt ...string) echo.MiddlewareFunc {
	return wrapMiddleware(core.CrossOriginEmbedderPolicy(opt...))
}

// CrossOriginResourcePolicy (CORP) helps isolate your document from other origins
func CrossOriginResourcePolicy(opt ...string) echo.MiddlewareFunc {
	return wrapMiddleware(core.CrossOriginResourcePolicy(opt...))
}

// PermissionsPolicy sets the Permissions Policy header to control which browser features can be used
func PermissionsPolicy(policy string) echo.MiddlewareFunc {
	return wrapMiddleware(core.PermissionsPolicy(policy))
}

// ClearSiteData clears specific types of data from the browser
func ClearSiteData(types ...string) echo.MiddlewareFunc {
	return wrapMiddleware(core.ClearSiteData(types...))
}
