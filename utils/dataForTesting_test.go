package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadEncryptionKeys(t *testing.T) {
	v, err := GetEncryptionKeysForTesting()

	assert.NotEmpty(t,v,"data loaded")
	assert.NotNil(t,v[0],"data loaded")
	assert.NotNil(t,v[0].ID,"data loaded")
	assert.NotEqual(t,v[0].OwnerUserId,"")
	assert.Equal(t, err, nil, "OK individual loaded")

}