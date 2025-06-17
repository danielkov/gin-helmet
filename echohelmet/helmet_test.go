package echohelmet

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func assertEqual[T comparable](t *testing.T, expected T, actual T) {
	if expected != actual {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}

// setupTestServer creates a test server with the given middleware
func setupTestServer(middleware echo.MiddlewareFunc) *httptest.Server {
	e := echo.New()

	// Add the middleware
	e.Use(middleware)

	// Simple test handler
	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	return httptest.NewServer(e)
}

func TestNoSniff(t *testing.T) {
	server := setupTestServer(NoSniff())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
}

func TestNoRobotIndex(t *testing.T) {
	server := setupTestServer(NoRobotIndex())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "noindex", resp.Header.Get("X-Robots-Tag"))
}

func TestDNSPrefetchControl(t *testing.T) {
	server := setupTestServer(DNSPrefetchControl())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "off", resp.Header.Get("X-DNS-Prefetch-Control"))
}

func TestFrameGuardDefault(t *testing.T) {
	server := setupTestServer(FrameGuard())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "DENY", resp.Header.Get("X-Frame-Options"))
}

func TestFrameGuardCustom(t *testing.T) {
	server := setupTestServer(FrameGuard("SAMEORIGIN"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "SAMEORIGIN", resp.Header.Get("X-Frame-Options"))
}

func TestSetHSTSDefault(t *testing.T) {
	server := setupTestServer(SetHSTS(true))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "max-age=5184000; includeSubDomains", resp.Header.Get("Strict-Transport-Security"))
}

func TestSetHSTSWithoutSubDomains(t *testing.T) {
	server := setupTestServer(SetHSTS(false))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "max-age=5184000", resp.Header.Get("Strict-Transport-Security"))
}

func TestSetHSTSCustomMaxAge(t *testing.T) {
	server := setupTestServer(SetHSTS(true, 31536000))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "max-age=31536000; includeSubDomains", resp.Header.Get("Strict-Transport-Security"))
}

func TestIENoOpen(t *testing.T) {
	server := setupTestServer(IENoOpen())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "noopen", resp.Header.Get("X-Download-Options"))
}

func TestXSSFilter(t *testing.T) {
	server := setupTestServer(XSSFilter())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
}

func TestReferrerDefault(t *testing.T) {
	server := setupTestServer(Referrer())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "strict-origin-when-cross-origin", resp.Header.Get("Referrer-Policy"))
}

func TestReferrerCustom(t *testing.T) {
	server := setupTestServer(Referrer("no-referrer"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "no-referrer", resp.Header.Get("Referrer-Policy"))
}

func TestNoCache(t *testing.T) {
	server := setupTestServer(NoCache())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "no-store", resp.Header.Get("Surrogate-Control"))
	assertEqual(t, "no-store, no-cache, must-revalidate, proxy-revalidate", resp.Header.Get("Cache-Control"))
	assertEqual(t, "no-cache", resp.Header.Get("Pragma"))
	assertEqual(t, "0", resp.Header.Get("Expires"))
}

func TestContentSecurityPolicy(t *testing.T) {
	server := setupTestServer(ContentSecurityPolicy(
		CSP("default-src", "'self'"),
		CSP("img-src", "*"),
		CSP("media-src", "media1.com media2.com"),
		CSP("script-src", "userscripts.example.com"),
	))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	expected := "default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com"
	assertEqual(t, expected, resp.Header.Get("Content-Security-Policy"))
}

func TestContentSecurityPolicyLegacy(t *testing.T) {
	server := setupTestServer(ContentSecurityPolicyLegacy(
		CSP("default-src", "'self'"),
		CSP("script-src", "'self' 'unsafe-inline'"),
	))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	expected := "default-src 'self'; script-src 'self' 'unsafe-inline'"
	assertEqual(t, expected, resp.Header.Get("Content-Security-Policy"))
	assertEqual(t, expected, resp.Header.Get("X-Webkit-CSP"))
	assertEqual(t, expected, resp.Header.Get("X-Content-Security-Policy"))
}

func TestExpectCT(t *testing.T) {
	server := setupTestServer(ExpectCT(86400, true, "https://example.com/report"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	expected := "enforce, report-uri=https://example.com/report, max-age=86400"
	assertEqual(t, expected, resp.Header.Get("Expect-CT"))
}

func TestExpectCTWithoutEnforce(t *testing.T) {
	server := setupTestServer(ExpectCT(86400, false))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	expected := "max-age=86400"
	assertEqual(t, expected, resp.Header.Get("Expect-CT"))
}

func TestSetHPKP(t *testing.T) {
	keys := []string{"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=", "M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="}
	server := setupTestServer(SetHPKP(keys, 5184000, true, "https://example.com/report"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	headerValue := resp.Header.Get("Public-Key-Pins")

	assertEqual(t, "pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; pin-sha256=\"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=\"; max-age=5184000; includeSubDomains; report-uri=\"https://example.com/report\"", headerValue)
}

func TestCrossOriginOpenerPolicyDefault(t *testing.T) {
	server := setupTestServer(CrossOriginOpenerPolicy())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "same-origin", resp.Header.Get("Cross-Origin-Opener-Policy"))
}

func TestCrossOriginOpenerPolicyCustom(t *testing.T) {
	server := setupTestServer(CrossOriginOpenerPolicy("unsafe-none"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "unsafe-none", resp.Header.Get("Cross-Origin-Opener-Policy"))
}

func TestCrossOriginEmbedderPolicyDefault(t *testing.T) {
	server := setupTestServer(CrossOriginEmbedderPolicy())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "require-corp", resp.Header.Get("Cross-Origin-Embedder-Policy"))
}

func TestCrossOriginEmbedderPolicyCustom(t *testing.T) {
	server := setupTestServer(CrossOriginEmbedderPolicy("credentialless"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "credentialless", resp.Header.Get("Cross-Origin-Embedder-Policy"))
}

func TestCrossOriginResourcePolicyDefault(t *testing.T) {
	server := setupTestServer(CrossOriginResourcePolicy())
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "cross-origin", resp.Header.Get("Cross-Origin-Resource-Policy"))
}

func TestCrossOriginResourcePolicyCustom(t *testing.T) {
	server := setupTestServer(CrossOriginResourcePolicy("same-origin"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "same-origin", resp.Header.Get("Cross-Origin-Resource-Policy"))
}

func TestPermissionsPolicy(t *testing.T) {
	policy := "geolocation=(), microphone=(), camera=()"
	server := setupTestServer(PermissionsPolicy(policy))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, policy, resp.Header.Get("Permissions-Policy"))
}

func TestClearSiteData(t *testing.T) {
	server := setupTestServer(ClearSiteData("cache", "cookies", "storage"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "\"cache\", \"cookies\", \"storage\"", resp.Header.Get("Clear-Site-Data"))
}

func TestClearSiteDataAll(t *testing.T) {
	server := setupTestServer(ClearSiteData("*"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "\"*\"", resp.Header.Get("Clear-Site-Data"))
}

func TestDefault(t *testing.T) {
	// Test that Default() returns multiple middlewares
	middlewares := Default()
	if len(middlewares) == 0 {
		t.Error("Default() should return at least one middleware")
	}

	// Create an Echo instance with all default middlewares
	e := echo.New()

	for _, middleware := range middlewares {
		e.Use(middleware)
	}

	// Simple test handler
	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	server := httptest.NewServer(e)
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Check that the expected headers are set
	assertEqual(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assertEqual(t, "off", resp.Header.Get("X-DNS-Prefetch-Control"))
	assertEqual(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assertEqual(t, "max-age=5184000; includeSubDomains", resp.Header.Get("Strict-Transport-Security"))
	assertEqual(t, "noopen", resp.Header.Get("X-Download-Options"))
	assertEqual(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
}

func TestCSPHelper(t *testing.T) {
	result := CSP("default-src", "'self'")
	assertEqual(t, "default-src 'self'", result)
}

func TestEchoHeaderWriter_SetHeader(t *testing.T) {
	e := echo.New()

	e.GET("/test", func(c echo.Context) error {
		writer := &EchoHeaderWriter{ctx: c}
		writer.SetHeader("Test-Header", "test-value")
		return c.String(http.StatusOK, "OK")
	})

	server := httptest.NewServer(e)
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, "test-value", resp.Header.Get("Test-Header"))
}

func TestEchoHeaderWriter_Next(t *testing.T) {
	e := echo.New()

	e.GET("/test", func(c echo.Context) error {
		writer := &EchoHeaderWriter{ctx: c}
		// Next() should not panic and should complete without error
		writer.Next()
		return c.String(http.StatusOK, "OK")
	})

	server := httptest.NewServer(e)
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	assertEqual(t, http.StatusOK, resp.StatusCode)
}
