package ginhelmet

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func assertEqual[T comparable](t *testing.T, expected T, actual T) {
	if expected != actual {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}

func getTestCaseFor(c func() gin.HandlerFunc) *httptest.ResponseRecorder {
	gin.SetMode(gin.ReleaseMode) // Suppress debug logs in tests
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(c())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	return w
}

func TestNoSniff(t *testing.T) {
	w := getTestCaseFor(NoSniff)
	assertEqual(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
}

func TestNoRobotIndex(t *testing.T) {
	w := getTestCaseFor(NoRobotIndex)
	assertEqual(t, "noindex", w.Header().Get("X-Robots-Tag"))
}

func TestDNSPrefetchControl(t *testing.T) {
	w := getTestCaseFor(DNSPrefetchControl)
	assertEqual(t, "off", w.Header().Get("X-DNS-Prefetch-Control"))
}

func TestFrameGuardDefault(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(FrameGuard())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	assertEqual(t, "DENY", w.Header().Get("X-Frame-Options"))
}

func TestFrameGuardCustom(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(FrameGuard("SAMEORIGIN"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	assertEqual(t, "SAMEORIGIN", w.Header().Get("X-Frame-Options"))
}

func TestSetHSTSDefault(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return SetHSTS(true) })
	assertEqual(t, "max-age=5184000; includeSubDomains", w.Header().Get("Strict-Transport-Security"))
}

func TestSetHSTSWithoutSubDomains(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return SetHSTS(false) })
	assertEqual(t, "max-age=5184000", w.Header().Get("Strict-Transport-Security"))
}

func TestSetHSTSCustomMaxAge(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return SetHSTS(true, 31536000) })
	assertEqual(t, "max-age=31536000; includeSubDomains", w.Header().Get("Strict-Transport-Security"))
}

func TestIENoOpen(t *testing.T) {
	w := getTestCaseFor(IENoOpen)
	assertEqual(t, "noopen", w.Header().Get("X-Download-Options"))
}

func TestXSSFilter(t *testing.T) {
	w := getTestCaseFor(XSSFilter)
	assertEqual(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
}

func TestReferrerDefault(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return Referrer() })
	assertEqual(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
}

func TestReferrerCustom(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return Referrer("no-referrer") })
	assertEqual(t, "no-referrer", w.Header().Get("Referrer-Policy"))
}

func TestNoCache(t *testing.T) {
	w := getTestCaseFor(NoCache)
	assertEqual(t, "no-store", w.Header().Get("Surrogate-Control"))
	assertEqual(t, "no-store, no-cache, must-revalidate, proxy-revalidate", w.Header().Get("Cache-Control"))
	assertEqual(t, "no-cache", w.Header().Get("Pragma"))
	assertEqual(t, "0", w.Header().Get("Expires"))
}

func TestDefault(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(Default())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	assertEqual(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assertEqual(t, "off", w.Header().Get("X-DNS-Prefetch-Control"))
	assertEqual(t, "DENY", w.Header().Get("X-Frame-Options"))
	assertEqual(t, "max-age=5184000; includeSubDomains", w.Header().Get("Strict-Transport-Security"))
	assertEqual(t, "noopen", w.Header().Get("X-Download-Options"))
	assertEqual(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
}

func TestContentSecurityPolicy(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(ContentSecurityPolicy(
		CSP("default-src", "'self'"),
		CSP("img-src", "*"),
		CSP("media-src", "media1.com media2.com"),
		CSP("script-src", "userscripts.example.com"),
	))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	expected := "default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com"
	assertEqual(t, expected, w.Header().Get("Content-Security-Policy"))
}

func TestContentSecurityPolicyLegacy(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(ContentSecurityPolicyLegacy(
		CSP("default-src", "'self'"),
		CSP("script-src", "'self' 'unsafe-inline'"),
	))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	expected := "default-src 'self'; script-src 'self' 'unsafe-inline'"
	assertEqual(t, expected, w.Header().Get("Content-Security-Policy"))
	assertEqual(t, expected, w.Header().Get("X-Webkit-CSP"))
	assertEqual(t, expected, w.Header().Get("X-Content-Security-Policy"))
}

func TestExpectCT(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return ExpectCT(86400, true, "https://example.com/report") })
	expected := "enforce, report-uri=https://example.com/report, max-age=86400"
	assertEqual(t, expected, w.Header().Get("Expect-CT"))
}

func TestExpectCTWithoutEnforce(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return ExpectCT(86400, false) })
	expected := "max-age=86400"
	assertEqual(t, expected, w.Header().Get("Expect-CT"))
}

func TestSetHPKP(t *testing.T) {
	keys := []string{"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=", "M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="}
	w := getTestCaseFor(func() gin.HandlerFunc { return SetHPKP(keys, 5184000, true, "https://example.com/report") })

	headerValue := w.Header().Get("Public-Key-Pins")
	expected := "pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; pin-sha256=\"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=\"; max-age=5184000; includeSubDomains; report-uri=\"https://example.com/report\""
	assertEqual(t, expected, headerValue)
}

func TestCrossOriginOpenerPolicyDefault(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return CrossOriginOpenerPolicy() })
	assertEqual(t, "same-origin", w.Header().Get("Cross-Origin-Opener-Policy"))
}

func TestCrossOriginOpenerPolicyCustom(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return CrossOriginOpenerPolicy("unsafe-none") })
	assertEqual(t, "unsafe-none", w.Header().Get("Cross-Origin-Opener-Policy"))
}

func TestCrossOriginEmbedderPolicyDefault(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return CrossOriginEmbedderPolicy() })
	assertEqual(t, "require-corp", w.Header().Get("Cross-Origin-Embedder-Policy"))
}

func TestCrossOriginEmbedderPolicyCustom(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return CrossOriginEmbedderPolicy("credentialless") })
	assertEqual(t, "credentialless", w.Header().Get("Cross-Origin-Embedder-Policy"))
}

func TestCrossOriginResourcePolicyDefault(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return CrossOriginResourcePolicy() })
	assertEqual(t, "cross-origin", w.Header().Get("Cross-Origin-Resource-Policy"))
}

func TestCrossOriginResourcePolicyCustom(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return CrossOriginResourcePolicy("same-origin") })
	assertEqual(t, "same-origin", w.Header().Get("Cross-Origin-Resource-Policy"))
}

func TestPermissionsPolicy(t *testing.T) {
	policy := "geolocation=(), microphone=(), camera=()"
	w := getTestCaseFor(func() gin.HandlerFunc { return PermissionsPolicy(policy) })
	assertEqual(t, policy, w.Header().Get("Permissions-Policy"))
}

func TestClearSiteData(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return ClearSiteData("cache", "cookies", "storage") })
	assertEqual(t, "\"cache\", \"cookies\", \"storage\"", w.Header().Get("Clear-Site-Data"))
}

func TestClearSiteDataAll(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return ClearSiteData("*") })
	assertEqual(t, "\"*\"", w.Header().Get("Clear-Site-Data"))
}

func TestCSPHelper(t *testing.T) {
	result := CSP("default-src", "'self'")
	assertEqual(t, "default-src 'self'", result)
}

func TestGinHeaderWriter_SetHeader(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		writer := &GinHeaderWriter{ctx: c}
		writer.SetHeader("Test-Header", "test-value")
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	assertEqual(t, "test-value", w.Header().Get("Test-Header"))
}

func TestGinHeaderWriter_Next(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	nextCalled := false
	r := gin.New()
	r.Use(func(c *gin.Context) {
		writer := &GinHeaderWriter{ctx: c}
		writer.Next()
		nextCalled = true
	})
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	assertEqual(t, true, nextCalled)
	assertEqual(t, 200, w.Code)
}
