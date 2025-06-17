package main

import (
	"github.com/danielkov/gin-helmet/ginhelmet"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Use all default security headers
	r.Use(ginhelmet.Default())

	// Or use individual middleware
	r.Use(ginhelmet.NoRobotIndex())
	r.Use(ginhelmet.ContentSecurityPolicy(
		ginhelmet.CSP("default-src", "'self'"),
		ginhelmet.CSP("img-src", "*"),
		ginhelmet.CSP("script-src", "'self' 'unsafe-inline'"),
	))

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message":   "Hello, World!",
			"framework": "Gin",
		})
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "healthy",
		})
	})

	r.Run(":8080")
}
