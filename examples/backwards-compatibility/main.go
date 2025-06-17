package main

import (
	"log"

	// This is the old import path - still works for backwards compatibility
	ginhelmet "github.com/danielkov/gin-helmet"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Using the old API - still works but shows deprecation warnings
	r.Use(ginhelmet.NoSniff())
	r.Use(ginhelmet.FrameGuard())
	r.Use(ginhelmet.SetHSTS(true))

	// Or use the default security headers
	// r.Use(ginhelmet.Default())

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello World!",
			"note":    "This example uses the deprecated import for backwards compatibility",
		})
	})

	log.Println("Server running on :8080")
	log.Println("Note: Using deprecated import path - please migrate to github.com/danielkov/gin-helmet/ginhelmet")
	r.Run(":8080")
}
