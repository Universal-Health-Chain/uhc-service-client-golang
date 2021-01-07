package commonManagers

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

const BytesPngForTestingInBase64 = "iVBORw0KGgoAAAANSUhEUgAAAOEAAADhCAMAAAAJbSJIAAAAA1BMVEX///+nxBvIAAAASElEQVR4nO3BgQAAAADDoPlTX+AIVQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADwDcaiAAFXD1ujAAAAAElFTkSuQmCC"
const BytesPngForTestingSHA1Hex = "2f5ba89f54930af881dbeab74599c3366fd37926"
const BytesPngForTestingSHA1Base64 = "L1uon1STCviB2+q3RZnDNm/TeSY="

func Test_FhirDocReferenceByAttachedBytesPDF(t *testing.T){
	fileBytes, err := Base64StringToBytes(BytesPngForTestingInBase64)
	require.NoError(t, err)
	mimeType := "image/png"
	language := "es"
	categoryCode := "test"
	fhir, err := FhirDocReferenceByAttachedBytesPDF(&fileBytes, &mimeType, &language, &categoryCode )
	require.NoError(t, err)
	// require.Equal(t, fhir.Language, language) // Expected :*string((*string)(0xc000173ce0)), Received :"es"

	// converting to json
	fhirBytes, err := json.Marshal(fhir)
	require.NoError(t, err)
	// fmt.Println("fhirBytes = ", fhirBytes)
	var fhirJson map[string]interface{}
	err = json.Unmarshal(fhirBytes, &fhirJson)
	require.NoError(t, err)
	fmt.Println("fhirJson = ", fhirJson)

	require.Equal(t, fhirJson["language"], language)

	categoryCodeable, ok := fhirJson["category"]
	require.True(t, ok)
	require.Len(t, categoryCodeable, 1)

}
