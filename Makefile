.PHONY: test test-verbose test-coverage clean

# Test all modules
test:
	@echo "Testing all modules..."
	@find . -name "go.mod" -execdir go test \;

# Test all modules with verbose output
test-verbose:
	@echo "Testing all modules (verbose)..."
	@find . -name "go.mod" -execdir go test -v \;

# Test all modules with coverage
test-coverage:
	@echo "Testing all modules with coverage..."
	@find . -name "go.mod" -execdir go test -cover \;

# Test specific modules that have tests
test-modules:
	@echo "Testing helmet modules..."
	@cd core && go test -cover
	@cd beegohelmet && go test -cover
	@cd echohelmet && go test -cover
	@cd fiberhelmet && go test -cover
	@cd ginhelmet && go test -cover
	@cd zerohelmet && go test -cover

# Clean all modules
clean:
	@echo "Cleaning all modules..."
	@find . -name "go.mod" -execdir go clean \; 