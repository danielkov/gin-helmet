package beegohelmet

import (
	"github.com/beego/beego/v2/server/web/context"
	"github.com/danielkov/gin-helmet/core"
)

// BeegoHeaderWriter implements core.HeaderWriter for Beego contexts
type BeegoHeaderWriter struct {
	ctx *context.Context
}

func (b *BeegoHeaderWriter) SetHeader(key, value string) {
	b.ctx.Output.Header(key, value)
}

func (b *BeegoHeaderWriter) Next() {
	// Beego middleware continue automatically
}

// BeegoMiddleware is a Beego middleware function type
type BeegoMiddleware func(*context.Context)

// wrapMiddleware converts a core.MiddlewareFunc to BeegoMiddleware
func wrapMiddleware(middleware core.MiddlewareFunc) BeegoMiddleware {
	return func(ctx *context.Context) {
		writer := &BeegoHeaderWriter{ctx: ctx}
		middleware(writer)
	}
}

// NoRobotIndex applies header to protect your server from robot indexation
func NoRobotIndex() BeegoMiddleware {
	return wrapMiddleware(core.NoRobotIndex())
}

// NoSniff applies header to protect your server from MimeType Sniffing
func NoSniff() BeegoMiddleware {
	return wrapMiddleware(core.NoSniff())
}

// DNSPrefetchControl sets Prefetch Control header to prevent browser from prefetching DNS
func DNSPrefetchControl() BeegoMiddleware {
	return wrapMiddleware(core.DNSPrefetchControl())
}

// FrameGuard sets Frame Options header to deny to prevent content from the website to be served in an iframe
func FrameGuard(opt ...string) BeegoMiddleware {
	return wrapMiddleware(core.FrameGuard(opt...))
}

// SetHSTS Sets Strict Transport Security header to the default of 60 days
// an optional integer may be added as a parameter to set the amount in seconds
func SetHSTS(sub bool, opt ...int) BeegoMiddleware {
	return wrapMiddleware(core.SetHSTS(sub, opt...))
}

// IENoOpen sets Download Options header for Internet Explorer to prevent it from executing downloads in the site's context
func IENoOpen() BeegoMiddleware {
	return wrapMiddleware(core.IENoOpen())
}

// XSSFilter applies very minimal XSS protection via setting the XSS Protection header on
// NOTE: X-XSS-Protection is deprecated. Use Content Security Policy instead.
func XSSFilter() BeegoMiddleware {
	return wrapMiddleware(core.XSSFilter())
}

// Default returns middleware functions that are advised to use for basic HTTP(s) protection
func Default() []BeegoMiddleware {
	coreMiddlewares := core.Default()
	result := make([]BeegoMiddleware, len(coreMiddlewares))
	for i, mw := range coreMiddlewares {
		result[i] = wrapMiddleware(mw)
	}
	return result
}

// Referrer sets the Referrer Policy header to prevent the browser from sending data from your website to another one upon navigation
// an optional string can be provided to set the policy to something else other than "strict-origin-when-cross-origin".
func Referrer(opt ...string) BeegoMiddleware {
	return wrapMiddleware(core.Referrer(opt...))
}

// NoCache obliterates cache options by setting a number of headers. This prevents the browser from storing your assets in cache
func NoCache() BeegoMiddleware {
	return wrapMiddleware(core.NoCache())
}

// ContentSecurityPolicy sets a header which will restrict your browser to only allow certain sources for assets on your website
/*
Example usage:
	web.InsertFilter("*", web.BeforeRouter, beegohelmet.ContentSecurityPolicy(
		beegohelmet.CSP("default-src", "'self'"),
		beegohelmet.CSP("img-src", "*"),
		beegohelmet.CSP("media-src", "media1.com media2.com"),
		beegohelmet.CSP("script-src", "userscripts.example.com"),
	))

See [Content Security Policy on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) for more info.
*/
func ContentSecurityPolicy(opts ...string) BeegoMiddleware {
	return wrapMiddleware(core.ContentSecurityPolicy(opts...))
}

func CSP(key, value string) string {
	return core.CSP(key, value)
}

func ContentSecurityPolicyLegacy(opts ...string) BeegoMiddleware {
	return wrapMiddleware(core.ContentSecurityPolicyLegacy(opts...))
}

// ExpectCT sets Certificate Transparency header which can enforce that you're using a Certificate which is ready for the
// upcoming Chrome requirements policy. The function accepts a maxAge int which is the TTL for the policy in delta seconds,
// an enforce boolean, which simply adds an enforce directive to the policy (otherwise it's report-only mode) and a
// optional reportUri, which is the URI to which report information is sent when the policy is violated.
// NOTE: Expect-CT is deprecated as of June 2021.
func ExpectCT(maxAge int, enforce bool, reportURI ...string) BeegoMiddleware {
	return wrapMiddleware(core.ExpectCT(maxAge, enforce, reportURI...))
}

// SetHPKP sets HTTP Public Key Pinning for your server. It is not necessarily a great thing to set this without proper
// knowledge of what this does. [Read here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning) otherwise you
// may likely end up DoS-ing your own server and domain. The function accepts a map of directives and their values according
// to specifications.
// NOTE: HPKP is deprecated and not recommended for use.
func SetHPKP(keys []string, maxAge int, sub bool, reportURI ...string) BeegoMiddleware {
	return wrapMiddleware(core.SetHPKP(keys, maxAge, sub, reportURI...))
}

// CrossOriginOpenerPolicy (COOP) helps isolate your document from other origins
func CrossOriginOpenerPolicy(opt ...string) BeegoMiddleware {
	return wrapMiddleware(core.CrossOriginOpenerPolicy(opt...))
}

// CrossOriginEmbedderPolicy (COEP) helps isolate your document from other origins
func CrossOriginEmbedderPolicy(opt ...string) BeegoMiddleware {
	return wrapMiddleware(core.CrossOriginEmbedderPolicy(opt...))
}

// CrossOriginResourcePolicy (CORP) helps isolate your document from other origins
func CrossOriginResourcePolicy(opt ...string) BeegoMiddleware {
	return wrapMiddleware(core.CrossOriginResourcePolicy(opt...))
}

// PermissionsPolicy sets the Permissions Policy header to control which browser features can be used
func PermissionsPolicy(policy string) BeegoMiddleware {
	return wrapMiddleware(core.PermissionsPolicy(policy))
}

// ClearSiteData clears specific types of data from the browser
func ClearSiteData(types ...string) BeegoMiddleware {
	return wrapMiddleware(core.ClearSiteData(types...))
}
