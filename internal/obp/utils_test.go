package obp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePassword(t *testing.T) {
	password := generatePassword(12, 1, 1, 1, 1)
	assert.Equal(t, 12, len(password))
	assert.True(t, strings.ContainsAny(password, specialCharSet))
	assert.True(t, strings.ContainsAny(password, lowerCharSet))
	assert.True(t, strings.ContainsAny(password, upperCharSet))
	assert.True(t, strings.ContainsAny(password, numberSet))
}
