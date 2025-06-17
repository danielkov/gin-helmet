# Backwards Compatibility Example

This example demonstrates how the original `github.com/danielkov/gin-helmet` import continues to work for backwards compatibility, even though the project has been restructured into a monorepo.

## What's Happening

The root module now re-exports all functions from the new `github.com/danielkov/gin-helmet/ginhelmet` module with deprecation notices. This means:

1. **Existing code continues to work** - No breaking changes
2. **Deprecation warnings** guide users to migrate
3. **Same function signatures** - No API changes required

## Migration Path

### Old way (still works, but deprecated):

```go
import ginhelmet "github.com/danielkov/gin-helmet"

r.Use(ginhelmet.NoSniff())
r.Use(ginhelmet.FrameGuard())
```

### New way (recommended):

```go
import "github.com/danielkov/gin-helmet/ginhelmet"

r.Use(ginhelmet.NoSniff())
r.Use(ginhelmet.FrameGuard())
```

## Running This Example

```bash
cd examples/backwards-compatibility
go run main.go
```

Your IDE/editor should show deprecation warnings for the old import path, guiding you to migrate to the new structure.

## Benefits of the New Structure

- **Framework-specific modules**: Use only what you need
- **Shared core logic**: Common security middleware logic
- **Better organization**: Clear separation between frameworks
- **Future-proof**: Easy to add new framework support
