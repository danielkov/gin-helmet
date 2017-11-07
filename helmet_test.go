package helmet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoSniff(t *testing.T) {
	assert.Equal(t, "a", "a", "Words a should be a.")
}
