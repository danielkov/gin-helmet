module github.com/danielkov/gin-helmet/beegohelmet

go 1.21

require (
	github.com/beego/beego/v2 v2.1.4
	github.com/danielkov/gin-helmet/core v1.0.1
)

require (
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/danielkov/gin-helmet/core => ../core
