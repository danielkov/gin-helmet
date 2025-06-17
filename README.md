# gin-helmet

A modular security middleware collection for Go web frameworks, inspired by [helmet.js](https://helmetjs.github.io/).

## Overview

This package provides HTTP security middleware for multiple Go web frameworks through a core abstraction layer. Each framework has its own implementation package that wraps the core functionality.

## Architecture

- **`core/`** - Framework-agnostic security middleware logic
- **`ginhelmet/`** - Gin framework implementation
- **`echohelmet/`** - Echo framework implementation
- **`beegohelmet/`** - Beego framework implementation
- **`zerohelmet/`** - Go-Zero framework implementation
- **`fiberhelmet/`** - Fiber framework implementation

## Supported Frameworks

| Framework                                       | Package       | Usage                                                |
| ----------------------------------------------- | ------------- | ---------------------------------------------------- |
| [Gin](https://github.com/gin-gonic/gin)         | `ginhelmet`   | `go get github.com/danielkov/gin-helmet/ginhelmet`   |
| [Echo](https://github.com/labstack/echo)        | `echohelmet`  | `go get github.com/danielkov/gin-helmet/echohelmet`  |
| [Beego](https://github.com/beego/beego)         | `beegohelmet` | `go get github.com/danielkov/gin-helmet/beegohelmet` |
| [Go-Zero](https://github.com/zeromicro/go-zero) | `zerohelmet`  | `go get github.com/danielkov/gin-helmet/zerohelmet`  |
| [Fiber](https://github.com/gofiber/fiber)       | `fiberhelmet` | `go get github.com/danielkov/gin-helmet/fiberhelmet` |

## Quick Start

### Gin Example

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/danielkov/gin-helmet/ginhelmet"
)

func main() {
    r := gin.Default()

    // Use default security headers
    r.Use(ginhelmet.Default())

    // Or use individual middleware
    r.Use(ginhelmet.NoSniff())
    r.Use(ginhelmet.FrameGuard())

    r.GET("/", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello, World!"})
    })

    r.Run()
}
```

### Echo Example

```go
package main

import (
    "github.com/labstack/echo/v4"
    "github.com/danielkov/gin-helmet/echohelmet"
)

func main() {
    e := echo.New()

    // Use default security headers
    for _, middleware := range echohelmet.Default() {
        e.Use(middleware)
    }

    e.GET("/", func(c echo.Context) error {
        return c.JSON(200, map[string]string{"message": "Hello, World!"})
    })

    e.Start(":8080")
}
```

### Fiber Example

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/danielkov/gin-helmet/fiberhelmet"
)

func main() {
    app := fiber.New()

    // Use default security headers
    for _, middleware := range fiberhelmet.Default() {
        app.Use(middleware)
    }

    app.Get("/", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"message": "Hello, World!"})
    })

    app.Listen(":8080")
}
```

## Available Middleware

All implementations provide the same security middleware functions:

- **`NoSniff()`** - Prevents MIME type sniffing
- **`DNSPrefetchControl()`** - Controls DNS prefetching
- **`FrameGuard()`** - Prevents clickjacking
- **`SetHSTS()`** - Enforces HTTPS connections
- **`IENoOpen()`** - Prevents IE from executing downloads
- **`XSSFilter()`** - Basic XSS protection (deprecated, use CSP instead)
- **`Referrer()`** - Controls referrer information
- **`NoCache()`** - Disables caching
- **`ContentSecurityPolicy()`** - Sets Content Security Policy
- **`ExpectCT()`** - Certificate Transparency (deprecated)
- **`SetHPKP()`** - HTTP Public Key Pinning (deprecated)
- **`CrossOriginOpenerPolicy()`** - COOP header
- **`CrossOriginEmbedderPolicy()`** - COEP header
- **`CrossOriginResourcePolicy()`** - CORP header
- **`PermissionsPolicy()`** - Controls browser features
- **`ClearSiteData()`** - Clears browser data
- **`Default()`** - Applies recommended security headers

## Content Security Policy Example

```go
// Gin
r.Use(ginhelmet.ContentSecurityPolicy(
    ginhelmet.CSP("default-src", "'self'"),
    ginhelmet.CSP("img-src", "*"),
    ginhelmet.CSP("script-src", "'self' 'unsafe-inline'"),
))

// Echo
e.Use(echohelmet.ContentSecurityPolicy(
    echohelmet.CSP("default-src", "'self'"),
    echohelmet.CSP("img-src", "*"),
    echohelmet.CSP("script-src", "'self' 'unsafe-inline'"),
))
```

## Benefits

- **No Framework Lock-in**: The core package has no framework dependencies
- **Consistent API**: Same function names and behavior across all frameworks
- **Minimal Dependencies**: Each framework package only pulls in what it needs
- **Easy Migration**: Switch between frameworks without changing security logic
- **Type Safety**: Full Go type safety and IDE support

## Writing Your Own Framework-Specific Helmet Adapter

```go
// MyHeaderWriter implements core.HeaderWriter for My framework contexts
type MyHeaderWriter struct {
	ctx myframework.Context
}

// SetHeader sets a header in the response - adopt this to your framework's context
func (m *MyHeaderWriter) SetHeader(key, value string) {
	m.ctx.Response().Header().Set(key, value)
}

// Next is called when the middleware is done - adopt this to your framework's context
func (m *MyHeaderWriter) Next() {
	m.ctx.Next()
}

// wrapMiddleware converts a core.MiddlewareFunc to myframework.MiddlewareFunc
func wrapMiddleware(middleware core.MiddlewareFunc) myframework.MiddlewareFunc {
	return func(next myframework.HandlerFunc) myframework.HandlerFunc {
		return func(c myframework.Context) error {
			writer := &MyHeaderWriter{ctx: c}
			middleware(writer)
			return next(c)
		}
	}
}

// You can copy/paste all of the functions from any of the existing framework-specific packages, e.g.: [echohelmet/helmet.go](echohelmet/helmet.go#L32)
// NoRobotIndex applies header to protect your server from robot indexation
func NoRobotIndex() BeegoMiddleware {
	return wrapMiddleware(core.NoRobotIndex())
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
