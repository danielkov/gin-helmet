package fiberhelmet

import (
	"github.com/danielkov/gin-helmet/core"
	"github.com/gofiber/fiber/v2"
)

// FiberHeaderWriter implements core.HeaderWriter for Fiber contexts
type FiberHeaderWriter struct {
	ctx *fiber.Ctx
}

func (f *FiberHeaderWriter) SetHeader(key, value string) {
	f.ctx.Set(key, value)
}

func (f *FiberHeaderWriter) Next() {
	// We don't call Next() here, as it's handled by the Fiber middleware system
}

// wrapMiddleware converts a core.MiddlewareFunc to fiber.Handler
func wrapMiddleware(middleware core.MiddlewareFunc) fiber.Handler {
	return func(c *fiber.Ctx) error {
		writer := &FiberHeaderWriter{ctx: c}
		middleware(writer)
		return c.Next()
	}
}

// NoRobotIndex applies header to protect your server from robot indexation
func NoRobotIndex() fiber.Handler {
	return wrapMiddleware(core.NoRobotIndex())
}

// NoSniff applies header to protect your server from MimeType Sniffing
func NoSniff() fiber.Handler {
	return wrapMiddleware(core.NoSniff())
}

// DNSPrefetchControl sets Prefetch Control header to prevent browser from prefetching DNS
func DNSPrefetchControl() fiber.Handler {
	return wrapMiddleware(core.DNSPrefetchControl())
}

// FrameGuard sets Frame Options header to deny to prevent content from the website to be served in an iframe
func FrameGuard(opt ...string) fiber.Handler {
	return wrapMiddleware(core.FrameGuard(opt...))
}

// SetHSTS Sets Strict Transport Security header to the default of 60 days
// an optional integer may be added as a parameter to set the amount in seconds
func SetHSTS(sub bool, opt ...int) fiber.Handler {
	return wrapMiddleware(core.SetHSTS(sub, opt...))
}

// IENoOpen sets Download Options header for Internet Explorer to prevent it from executing downloads in the site's context
func IENoOpen() fiber.Handler {
	return wrapMiddleware(core.IENoOpen())
}

// XSSFilter applies very minimal XSS protection via setting the XSS Protection header on
// NOTE: X-XSS-Protection is deprecated. Use Content Security Policy instead.
func XSSFilter() fiber.Handler {
	return wrapMiddleware(core.XSSFilter())
}

// Default returns middleware functions that are advised to use for basic HTTP(s) protection
func Default() []fiber.Handler {
	coreMiddlewares := core.Default()
	result := make([]fiber.Handler, len(coreMiddlewares))
	for i, mw := range coreMiddlewares {
		result[i] = wrapMiddleware(mw)
	}
	return result
}

// Referrer sets the Referrer Policy header to prevent the browser from sending data from your website to another one upon navigation
// an optional string can be provided to set the policy to something else other than "strict-origin-when-cross-origin".
func Referrer(opt ...string) fiber.Handler {
	return wrapMiddleware(core.Referrer(opt...))
}

// NoCache obliterates cache options by setting a number of headers. This prevents the browser from storing your assets in cache
func NoCache() fiber.Handler {
	return wrapMiddleware(core.NoCache())
}

// ContentSecurityPolicy sets a header which will restrict your browser to only allow certain sources for assets on your website
/*
Example usage:
	app := fiber.New()
	app.Use(fiberhelmet.ContentSecurityPolicy(
		fiberhelmet.CSP("default-src", "'self'"),
		fiberhelmet.CSP("img-src", "*"),
		fiberhelmet.CSP("media-src", "media1.com media2.com"),
		fiberhelmet.CSP("script-src", "userscripts.example.com"),
	))

See [Content Security Policy on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) for more info.
*/
func ContentSecurityPolicy(opts ...string) fiber.Handler {
	return wrapMiddleware(core.ContentSecurityPolicy(opts...))
}

func CSP(key, value string) string {
	return core.CSP(key, value)
}

func ContentSecurityPolicyLegacy(opts ...string) fiber.Handler {
	return wrapMiddleware(core.ContentSecurityPolicyLegacy(opts...))
}

// ExpectCT sets Certificate Transparency header which can enforce that you're using a Certificate which is ready for the
// upcoming Chrome requirements policy. The function accepts a maxAge int which is the TTL for the policy in delta seconds,
// an enforce boolean, which simply adds an enforce directive to the policy (otherwise it's report-only mode) and a
// optional reportUri, which is the URI to which report information is sent when the policy is violated.
// NOTE: Expect-CT is deprecated as of June 2021.
func ExpectCT(maxAge int, enforce bool, reportURI ...string) fiber.Handler {
	return wrapMiddleware(core.ExpectCT(maxAge, enforce, reportURI...))
}

// SetHPKP sets HTTP Public Key Pinning for your server. It is not necessarily a great thing to set this without proper
// knowledge of what this does. [Read here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning) otherwise you
// may likely end up DoS-ing your own server and domain. The function accepts a map of directives and their values according
// to specifications.
// NOTE: HPKP is deprecated and not recommended for use.
func SetHPKP(keys []string, maxAge int, sub bool, reportURI ...string) fiber.Handler {
	return wrapMiddleware(core.SetHPKP(keys, maxAge, sub, reportURI...))
}

// CrossOriginOpenerPolicy (COOP) helps isolate your document from other origins
func CrossOriginOpenerPolicy(opt ...string) fiber.Handler {
	return wrapMiddleware(core.CrossOriginOpenerPolicy(opt...))
}

// CrossOriginEmbedderPolicy (COEP) helps isolate your document from other origins
func CrossOriginEmbedderPolicy(opt ...string) fiber.Handler {
	return wrapMiddleware(core.CrossOriginEmbedderPolicy(opt...))
}

// CrossOriginResourcePolicy (CORP) helps isolate your document from other origins
func CrossOriginResourcePolicy(opt ...string) fiber.Handler {
	return wrapMiddleware(core.CrossOriginResourcePolicy(opt...))
}

// PermissionsPolicy sets the Permissions Policy header to control which browser features can be used
func PermissionsPolicy(policy string) fiber.Handler {
	return wrapMiddleware(core.PermissionsPolicy(policy))
}

// ClearSiteData clears specific types of data from the browser
func ClearSiteData(types ...string) fiber.Handler {
	return wrapMiddleware(core.ClearSiteData(types...))
}
