/* Copyright 2021 Fundación UNID */
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
	assert.Equal(t, err, nil, "OK individual loaded")

}