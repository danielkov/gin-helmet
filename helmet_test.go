package helmet

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func getTestCaseFor(c func() gin.HandlerFunc) *httptest.ResponseRecorder {
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
	if w.HeaderMap.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Failed to set X-Content-Type-Options header to nosniff.")
	}
}

func TestDNSPrefetchControl(t *testing.T) {
	w := getTestCaseFor(DNSPrefetchControl)
	if w.HeaderMap.Get("X-DNS-Prefetch-Control") != "off" {
		t.Errorf("Failed to set X-DNS-Prefetch-Control to off.")
	}
}

func TestFrameGuardDefault(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(FrameGuard())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	if w.HeaderMap.Get("X-Frame-Options") != "DENY" {
		t.Errorf("Failed to set X-Frame-Options to DENY by default.")
	}
}

func TestFrameGuard(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(FrameGuard("ALLOW-FROM https://example.com/"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	if w.HeaderMap.Get("X-Frame-Options") != "ALLOW-FROM https://example.com/" {
		t.Errorf("Failed to set X-Frame-Options to ALLOW-FROM https://example.com/ as per parameter.")
	}
}

func TestSetHSTSDefault(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(SetHSTS(false))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	if w.HeaderMap.Get("Strict-Transport-Security") != "max-age=5184000" {
		t.Errorf("Failed to set Strict-Transport-Security to max-age=5184000 by default.")
	}
}

func TestSetHSTSMaxAge(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(SetHSTS(false, 6000))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	if w.HeaderMap.Get("Strict-Transport-Security") != "max-age=6000" {
		t.Errorf("Failed to set Strict-Transport-Security to max-age=6000 as per parameter.")
	}
}

func TestSetHSTSSubDomains(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(SetHSTS(true))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	if w.HeaderMap.Get("Strict-Transport-Security") != "max-age=5184000; includeSubDomains" {
		t.Errorf("Failed to set Strict-Transport-Security to max-age=5184000 and includeSubdomains as per parameter.")
	}
}

func TestIENoOpen(t *testing.T) {
	w := getTestCaseFor(IENoOpen)

	if w.HeaderMap.Get("X-Download-Options") != "noopen" {
		t.Errorf("Failed to set X-Download-Options to noopen.")
	}
}

func TestXSSFilter(t *testing.T) {
	w := getTestCaseFor(XSSFilter)

	if w.HeaderMap.Get("X-XSS-Protection") != "1; mode=block" {
		t.Errorf("Failed to set X-XSS-Protection to 1; mode=block.")
	}
}

func TestDefault(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(Default())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	if w.HeaderMap.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Failed to set X-Content-Type-Options header to nosniff.")
	}
	if w.HeaderMap.Get("X-DNS-Prefetch-Control") != "off" {
		t.Errorf("Failed to set X-DNS-Prefetch-Control to off.")
	}
	if w.HeaderMap.Get("X-Frame-Options") != "DENY" {
		t.Errorf("Failed to set X-Frame-Options to DENY by default.")
	}
	if w.HeaderMap.Get("Strict-Transport-Security") != "max-age=5184000; includeSubDomains" {
		t.Errorf("Failed to set Strict-Transport-Security to max-age=5184000 and includeSubDomains by default.")
	}
	if w.HeaderMap.Get("X-Download-Options") != "noopen" {
		t.Errorf("Failed to set X-Download-Options to noopen.")
	}
	if w.HeaderMap.Get("X-XSS-Protection") != "1; mode=block" {
		t.Errorf("Failed to set X-XSS-Protection to 1; mode=block.")
	}
}

func TestRefereerDefault(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(Referrer())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	if w.HeaderMap.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Failed to set Referrer-Policy to no-referrer by default.")
	}
}

func TestReferrer(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(Referrer("same-origin"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	if w.HeaderMap.Get("Referrer-Policy") != "same-origin" {
		t.Errorf("Failed to set Referrer-Policy to same-origin as per parameter.")
	}
}

func TestNoCache(t *testing.T) {
	w := getTestCaseFor(NoCache)

	if w.HeaderMap.Get("Surrogate-Control") != "no-store" {
		t.Errorf("Failed to set Surrogate-Control to no-store.")
	}
	if w.HeaderMap.Get("Cache-Control") != "no-store, no-cache, must-revalidate, proxy-revalidate" {
		t.Errorf("Failed to set Cache-Control.")
	}
	if w.HeaderMap.Get("Pragma") != "no-cache" {
		t.Errorf("Failed to set Pragma to no-cache.")
	}
	if w.HeaderMap.Get("Expires") != "0" {
		t.Errorf("Failed to set Expires to 0.")
	}
}

func TestContentSecurityPolicy(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	opt := map[string]string{
		"default-src": "'self'",
		"img-src":     "*",
		"media-src":   "media1.com media2.com",
		"script-src":  "userscripts.example.com",
	}

	r := gin.New()
	r.Use(ContentSecurityPolicy(opt, false))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	fmt.Println(w.HeaderMap.Get("Content-Security-Policy"))

	v := []string{
		"default-src 'self'",
		"img-src *",
		"media-src media1.com media2.com",
		"script-src userscripts.example.com",
	}

	h := w.HeaderMap.Get("Content-Security-Policy")

	for _, b := range v {
		if !strings.Contains(h, b) {
			t.Errorf("Directive was not set on Content-Security-Policy header: %s", b)
		}
	}
}

func TestContentSecurityPolicyLegacy(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	opt := map[string]string{
		"default-src": "'self'",
		"img-src":     "*",
		"media-src":   "media1.com media2.com",
		"script-src":  "userscripts.example.com",
	}

	r := gin.New()
	r.Use(ContentSecurityPolicy(opt, true))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	a := w.HeaderMap.Get("Content-Security-Policy")
	b := w.HeaderMap.Get("X-Webkit-CSP")
	c := w.HeaderMap.Get("X-Content-Security-Policy")

	v := []string{
		"default-src 'self'",
		"img-src *",
		"media-src media1.com media2.com",
		"script-src userscripts.example.com",
	}

	for _, d := range v {
		if !strings.Contains(a, d) {
			t.Errorf("Directive was not set on Content-Security-Policy header: %s", d)
		}
		if !strings.Contains(b, d) {
			t.Errorf("Directive was not set on X-Webkit-CSP header: %s", d)
		}
		if !strings.Contains(c, d) {
			t.Errorf("Directive was not set on X-Content-Security-Policy header: %s", d)
		}
	}
}

func TestExpectCT(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(ExpectCT(50000, true, "domain.com"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	if w.HeaderMap.Get("Expect-CT") != "enforce, report-uri=domain.com, max-age=50000" {
		t.Errorf("Failed to set Expect-CT according to parameters.")
	}
}

func TestSetHPKP(t *testing.T) {
	keys := []string{"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=", "M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="}
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	r := gin.New()
	r.Use(SetHPKP(keys, 5184000, true, "domain.com"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"foo": "bar"})
	})

	r.ServeHTTP(w, req)

	if w.HeaderMap.Get("Public-Key-Pins") != "pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; pin-sha256=\"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=\"; max-age=5184000; includeSubDomains; report-uri=\"domain.com\"" {
		t.Errorf("Failed to set Public-Key-Pins according to parameters.")
	}
}
