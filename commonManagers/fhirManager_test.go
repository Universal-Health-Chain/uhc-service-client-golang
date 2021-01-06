package commonManagers

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const BytesPngForTestingInBase64 = "iVBORw0KGgoAAAANSUhEUgAAAOEAAADhCAMAAAAJbSJIAAAAA1BMVEX///+nxBvIAAAASElEQVR4nO3BgQAAAADDoPlTX+AIVQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADwDcaiAAFXD1ujAAAAAElFTkSuQmCC"
const BytesPngForTestingSHA1Hex = "2f5ba89f54930af881dbeab74599c3366fd37926"
const BytesPngForTestingSHA1Base64 = "L1uon1STCviB2+q3RZnDNm/TeSY="

func Test_FhirDocReferenceByAttachedBytesPDF(t *testing.T){
	fileBytes, err := Base64StringToBytes(BytesPngForTestingInBase64)
	assert.NoError(t, err)
	mimeType := "image/png"
	language := "es"
	categoryCode := "test"
	fhirDocReference, err := FhirDocReferenceByAttachedBytesPDF(&fileBytes, &mimeType, &language, &categoryCode )
	assert.NoError(t, err)
	assert.Equal(t, fhirDocReference.Language, language)
	// TODO
}
