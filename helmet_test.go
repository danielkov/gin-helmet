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

// Test basic backwards compatibility functions
func TestBackwardsCompatibility_NoSniff(t *testing.T) {
	w := getTestCaseFor(NoSniff)
	assertEqual(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
}

func TestBackwardsCompatibility_NoRobotIndex(t *testing.T) {
	w := getTestCaseFor(NoRobotIndex)
	assertEqual(t, "noindex", w.Header().Get("X-Robots-Tag"))
}

func TestBackwardsCompatibility_DNSPrefetchControl(t *testing.T) {
	w := getTestCaseFor(DNSPrefetchControl)
	assertEqual(t, "off", w.Header().Get("X-DNS-Prefetch-Control"))
}

func TestBackwardsCompatibility_FrameGuard(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return FrameGuard() })
	assertEqual(t, "DENY", w.Header().Get("X-Frame-Options"))
}

func TestBackwardsCompatibility_SetHSTS(t *testing.T) {
	w := getTestCaseFor(func() gin.HandlerFunc { return SetHSTS(true) })
	assertEqual(t, "max-age=5184000; includeSubDomains", w.Header().Get("Strict-Transport-Security"))
}

func TestBackwardsCompatibility_IENoOpen(t *testing.T) {
	w := getTestCaseFor(IENoOpen)
	assertEqual(t, "noopen", w.Header().Get("X-Download-Options"))
}

func TestBackwardsCompatibility_XSSFilter(t *testing.T) {
	w := getTestCaseFor(XSSFilter)
	assertEqual(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
}

func TestBackwardsCompatibility_Default(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(Default())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	// Check that some expected headers are set
	assertEqual(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assertEqual(t, "off", w.Header().Get("X-DNS-Prefetch-Control"))
	assertEqual(t, "DENY", w.Header().Get("X-Frame-Options"))
}

func TestBackwardsCompatibility_CSP(t *testing.T) {
	result := CSP("default-src", "'self'")
	assertEqual(t, "default-src 'self'", result)
}

func TestBackwardsCompatibility_ContentSecurityPolicy(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(ContentSecurityPolicy(
		CSP("default-src", "'self'"),
		CSP("script-src", "'self'"),
	))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	expected := "default-src 'self'; script-src 'self'"
	assertEqual(t, expected, w.Header().Get("Content-Security-Policy"))
}
