package models


// arrays are represented by string concatenation using ^ in the same way as HL7 v2 Messaging

type PatientAdministrativeIdentityClaim struct {
	PatientActive                     	*bool	`bson:"patientActive,omitempty" json:"patientActive,omitempty"`
	PatientAnimal                     	*bool	`bson:"patientAnimal,omitempty" json:"patientAnimal,omitempty"`	// false
	PatientBirthDate                  	*string	`bson:"patientBirthDate,omitempty" json:"patientBirthDate,omitempty"`	// FHIR date (not datetime), e.g. "1978-12-30"
	PatientBirthPlaceAddressCity      	*string	`bson:"patientBirthPlaceAddressCity,omitempty" json:"patientBirthPlaceAddressCity,omitempty"`	// e.g. "Soria"
	PatientBirthPlaceAddressCountry   	*string	`bson:"patientBirthPlaceAddressCountry,omitempty" json:"patientBirthPlaceAddressCountry,omitempty"`	// e.g. "ESP",
	PatientBirthPlaceAddressState   	*string	`bson:"patientBirthPlaceAddressState,omitempty" json:"omitempty"`	// e.g. "ESP",
	PatientCommunicationLanguageText  	*string	`bson:"patientCommunicationLanguageText,omitempty" json:"patientCommunicationLanguageText,omitempty"`	// some description about Communitation Language Codes,
	PatientCommunicationLanguageToken 	*string	`bson:"patientCommunicationLanguageToken,omitempty" json:"patientCommunicationLanguageTokenomitempty"`	// system|code (FHIR API's token format), e.g. "urn:ietf:bcp:47|es^urn:ietf:bcp:47|en",
	PatientCommunicationPreferenceType	*string	`bson:"patientCommunicationPreferenceType,omitempty" json:"patientCommunicationPreferenceType,omitempty"`	// e.g. email or phone
	PatientGenderAdministrative       	*string	`bson:"patientGenderAdministrative,omitempty" json:"patientGenderAdministrative,omitempty"`	// FHIR gender types http://hl7.org/fhir/valueset-administrative-gender.html
	PatientGenderBirth                	*string	`bson:"patientGenderBirth,omitempty" json:"patientGenderBirth,omitempty"`	// US core extension http://hl7.org/fhir/us/core/StructureDefinition/us-core-birthsex terminology http://hl7.org/fhir/us/core/ValueSet-birthsex.html
	PatientGenderIdentity             	*string `bson:"patientGenderIdentity,omitempty" json:"patientGenderIdentity,omitempty"`	// FHIR gender identity types extension terminology https://www.hl7.org/fhir/valueset-gender-identity.html
	PatientGeneralPractitioner        	*string `bson:"patientGeneralPractitioner,omitempty" json:"patientGeneralPractitioner,omitempty"`	// reference, e.g. "Practitioner/uuid or did",
	PatientId                         	*string `bson:"patientId,omitempty" json:"patientId,omitempty"`	// UUID v4
	PatientIdentifier                 	*string `bson:"patientIdentifier,omitempty" json:"patientIdentifier,omitempty"`	// e.g. for Spain: "urn:oid:1.3.6.1.4.1.19126.3|DNI123456"
	PatientIdentifierOfType           	*string `bson:"patientIdentifierOfType,omitempty" json:"patientIdentifierOfType,omitempty"`	// e.g. for Spain: "http://terminology.hl7.org/CodeSystem/v2-0203|NNESP|DNI123456"
	PatientInterpreterRequired        	*bool	`bson:"patientInterpreterRequired,omitempty" json:"patientInterpreterRequired,omitempty"`	// extension http://hl7.org/fhir/StructureDefinition/Patient-interpreterRequired
	PatientLinkReferenceWithType      	*string	`bson:"patientLinkReferenceWithType,omitempty" json:"patientLinkReferenceWithType,omitempty"`	// Includes type of reference, e.g. "Path/uuid|refer",
	PatientNameFamily                 	*string	`bson:"patientNameFamily,omitempty" json:"patientNameFamily,omitempty"`	// First surname
	PatientNameGiven                  	*string	`bson:"patientNameGiven,omitempty" json:"patientNameGiven,omitempty"`	// e.g. "Name1^Name2",
	PatientNameMothersFamily         	*string	`bson:"patientNameMothersFamily,omitempty" json:"patientNameMothersFamily,omitempty"`	// Second surname (e.g. Spain, Chile, Argentina)
	PatientPhotoBase64                	*string	`bson:"patientPhotoBase64,omitempty" json:"patientPhotoBase64,omitempty"`	// it corresponds to FHIR.Attachment.data: Data inline, base64ed
	PatientPhotoHashSha1              	*string	`bson:"patientPhotoHashSha1,omitempty" json:"patientPhotoHashSha1,omitempty"`	// it corresponds to FHIR.Attachment.hash: Hash of the data (sha-1, base64ed)
	PatientPhotoMimetype              	*string	`bson:"patientPhotoMimetype,omitempty" json:"patientPhotoMimetype,omitempty"`	// it corresponds to FHIR.Attachment.contentType
	PatientPhotoSizeBytes             	*int	`bson:"patientPhotoSizeBytes,omitempty" json:"patientPhotoSizeBytes,omitempty"`	// it corresponds to FHIR.Attachment.size: Number of bytes of content (if url provided)
	PatientPhotoUrl                   	*string	`bson:"patientPhotoUrl,omitempty" json:"patientPhotoUrl,omitempty"`	// it corresponds to FHIR.Attachment.url: Uri where the data can be found
	PatientRelatedPerson              	*string	`bson:"patientRelatedPerson,omitempty" json:"patientRelatedPerson,omitempty"`	// concatenation of references "Path/uuid or did" (extension https://www.hl7.org/fhir/extension-Patient-relatedperson.html)
	PatientTelecom                    	*string	`bson:"patientTelecom,omitempty" json:"patientTelecom,omitempty"`	// FHIR.Patient.Telecom using token concatenation, e.g.: "phone|+34123456789|mobile^email|personal@email.org|home"
}

type PatientClaimFHIR struct {
	PatientActive                     	*bool	`bson:"patientActive,omitempty" json:"patientActive,omitempty"`
	PatientAnimal                     	*bool	`bson:"patientAnimal,omitempty" json:"patientAnimal,omitempty"`	// false
	PatientBirthDate                  	*string	`bson:"patientBirthDate,omitempty" json:"patientBirthDate,omitempty"`	// FHIR date (not datetime), e.g. "1978-12-30"
	PatientBirthPlaceAddressCity      	*string	`bson:"patientBirthPlaceAddressCity,omitempty" json:"patientBirthPlaceAddressCity,omitempty"`	// e.g. "Soria"
	PatientBirthPlaceAddressCountry   	*string	`bson:"patientBirthPlaceAddressCountry,omitempty" json:"patientBirthPlaceAddressCountry,omitempty"`	// e.g. "ESP",
	PatientBirthPlaceAddressState   	*string	`bson:"patientBirthPlaceAddressState,omitempty" json:"omitempty"`	// e.g. "ESP",
	PatientCadavericDonor             	*bool	`bson:"patientCadavericDonor,omitempty" json:"patientCadavericDonor,omitempty"`	// extension: Flag indicating whether the Patient authorized the donation of body parts after death
	PatientCommunicationLanguageText  	*string	`bson:"patientCommunicationLanguageText,omitempty" json:"patientCommunicationLanguageText,omitempty"`	// some description about Communitation Language Codes,
	PatientCommunicationLanguageToken 	*string	`bson:"patientCommunicationLanguageToken,omitempty" json:"patientCommunicationLanguageTokenomitempty"`	// system|code (FHIR API's token format), e.g. "urn:ietf:bcp:47|es^urn:ietf:bcp:47|en",
	PatientCommunicationPreferenceType	*string	`bson:"patientCommunicationPreferenceType,omitempty" json:"patientCommunicationPreferenceType,omitempty"`	// e.g. email or phone
	PatientDeceasedBoolean            	*bool	`bson:"patientDeceasedBoolean,omitempty" json:"patientDeceasedBoolean,omitempty"`	// Choice one of them to indicate if the individual is deceased
	PatientDeceasedDateTime           	*string	`bson:"patientDeceasedDateTime,omitempty" json:"patientDeceasedDateTime,omitempty"`	// Choice one of them to indicate if the individual is deceased
	PatientGenderAdministrative       	*string	`bson:"patientGenderAdministrative,omitempty" json:"patientGenderAdministrative,omitempty"`	// FHIR gender types http://hl7.org/fhir/valueset-administrative-gender.html
	PatientGenderBirth                	*string	`bson:"patientGenderBirth,omitempty" json:"patientGenderBirth,omitempty"`	// US core extension http://hl7.org/fhir/us/core/StructureDefinition/us-core-birthsex terminology http://hl7.org/fhir/us/core/ValueSet-birthsex.html
	PatientGenderIdentity             	*string `bson:"patientGenderIdentity,omitempty" json:"patientGenderIdentity,omitempty"`	// FHIR gender identity types extension terminology https://www.hl7.org/fhir/valueset-gender-identity.html
	PatientGeneralPractitioner        	*string `bson:"patientGeneralPractitioner,omitempty" json:"patientGeneralPractitioner,omitempty"`	// reference, e.g. "Practitioner/uuid or did",
	PatientId                         	*string `bson:"patientId,omitempty" json:"patientId,omitempty"`	// UUID v4
	PatientIdentifier                 	*string `bson:"patientIdentifier,omitempty" json:"patientIdentifier,omitempty"`	// e.g. for Spain: "urn:oid:1.3.6.1.4.1.19126.3|DNI123456"
	PatientIdentifierOfType           	*string `bson:"patientIdentifierOfType,omitempty" json:"patientIdentifierOfType,omitempty"`	// e.g. for Spain: "http://terminology.hl7.org/CodeSystem/v2-0203|NNESP|DNI123456"
	PatientInterpreterRequired        	*bool	`bson:"patientInterpreterRequired,omitempty" json:"patientInterpreterRequired,omitempty"`	// extension http://hl7.org/fhir/StructureDefinition/Patient-interpreterRequired
	PatientLinkReferenceWithType      	*string	`bson:"patientLinkReferenceWithType,omitempty" json:"patientLinkReferenceWithType,omitempty"`	// Includes type of reference, e.g. "Path/uuid|refer",
	PatientMultipleBirthBoolean       	*bool	`bson:"patientMultipleBirthBoolean,omitempty" json:"patientMultipleBirthBoolean,omitempty"`	// Choice one of them when Patient is part of a multiple birth
	PatientMultipleBirthInteger       	*int	`bson:"patientMultipleBirthInteger,omitempty" json:"patientMultipleBirthInteger,omitempty"`	// Choice one of them when Patient is part of a multiple birth
	PatientNameFamily                 	*string	`bson:"patientNameFamily,omitempty" json:"patientNameFamily,omitempty"`	// First surname
	PatientNameGiven                  	*string	`bson:"patientNameGiven,omitempty" json:"patientNameGiven,omitempty"`	// e.g. "Name1^Name2",
	PatientNameMothersFamily         	*string	`bson:"patientNameMothersFamily,omitempty" json:"patientNameMothersFamily,omitempty"`	// Second surname (e.g. Spain, Chile, Argentina)
	PatientPhotoBase64                	*string	`bson:"patientPhotoBase64,omitempty" json:"patientPhotoBase64,omitempty"`	// it corresponds to FHIR.Attachment.data: Data inline, base64ed
	PatientPhotoHashSha1              	*string	`bson:"patientPhotoHashSha1,omitempty" json:"patientPhotoHashSha1,omitempty"`	// it corresponds to FHIR.Attachment.hash: Hash of the data (sha-1, base64ed)
	PatientPhotoMimetype              	*string	`bson:"patientPhotoMimetype,omitempty" json:"patientPhotoMimetype,omitempty"`	// it corresponds to FHIR.Attachment.contentType
	PatientPhotoSizeBytes             	*int	`bson:"patientPhotoSizeBytes,omitempty" json:"patientPhotoSizeBytes,omitempty"`	// it corresponds to FHIR.Attachment.size: Number of bytes of content (if url provided)
	PatientPhotoUrl                   	*string	`bson:"patientPhotoUrl,omitempty" json:"patientPhotoUrl,omitempty"`	// it corresponds to FHIR.Attachment.url: Uri where the data can be found
	PatientRelatedPerson              	*string	`bson:"patientRelatedPerson,omitempty" json:"patientRelatedPerson,omitempty"`	// concatenation of references "Path/uuid or did" (extension https://www.hl7.org/fhir/extension-Patient-relatedperson.html)
	PatientReligionText               	*string	`bson:"patientReligionText,omitempty" json:"patientReligionText,omitempty"`	// description of the Patient religion
	PatientReligionToken              	*string	`bson:"patientReligionToken,omitempty" json:"patientReligionToken,omitempty"`	// extension http://hl7.org/fhir/StructureDefinition/Patient-religion and terminology http://terminology.hl7.org/ValueSet/v3-ReligiousAffiliation
	PatientTelecom                    	*string	`bson:"patientTelecom,omitempty" json:"patientTelecom,omitempty"`	// FHIR.Patient.Telecom using token concatenation, e.g.: "phone|+34123456789|mobile^email|personal@email.org|home"
}

type AddressClaim struct {
	AddressCity				*string	`bson:"addressCity,omitempty" json:"addressCity,omitempty"`	// e.g. "Soria"
	AddressCountry			*string	`bson:"addressCountry,omitempty" json:"addressCountry,omitempty"`	// e.g. "ESP",
	AddressDistrict			*string	`bson:"addressDistrict,omitempty" json:"addressDistrict,omitempty"`	// e.g. "Soria"
	AddressLine				*string	`bson:"addressLine,omitempty" json:"addressLine,omitempty"`	// line1^line2 (street name, number, direction, etc.)
	AddressPeriod			*string	`bson:"addressPeriod,omitempty" json:"addressPeriod,omitempty"`	// datetime|datetime (time period when Address was/is in use)
	AddressPostalcode		*string	`bson:"addressPostalcode,omitempty" json:"addressPostalcode,omitempty"`	// postal code for area
	AddressState			*string	`bson:"addressState,omitempty" json:"addressState,omitempty"`	// e.g. "ES-CL"
	AddressText				*string	`bson:"addressText,omitempty" json:"addressText,omitempty"`	// text representation of the Address
	AddressType				*string	`bson:"addressType,omitempty" json:"addressType,omitempty"`	// postal | physical | both
	AddressUse				*string `bson:"addressUse,omitempty" json:"addressUse,omitempty"`	// purpose of this Address: home | work | temp | old | billing
}

// extension from https://www.hl7.org/fhir/Patient-extensions.html
type PatientCitizenshipClaim struct {
	PatientCitizenshipPeriod	*string	`bson:"patientCitizenshipPeriod,omitempty" json:"patientCitizenshipPeriod,omitempty"`	// extension from https://www.hl7.org/fhir/Patient-extensions.html
	PatientCitizenshipText		*string	`bson:"patientCitizenshipText,omitempty" json:"patientCitizenshipText,omitempty"`	// extension from https://www.hl7.org/fhir/Patient-extensions.html
	PatientCitizenshipToken		*string	`bson:"patientCitizenshipToken,omitempty" json:"patientCitizenshipToken,omitempty"`	// system|code (FHIR API's token format)
}

// extension from https://www.hl7.org/fhir/extension-Patient-nationality.html
type PatientNationalityClaim struct {
	PatientNationalityPeriod	*string	`bson:"patientNationalityPeriod,omitempty" json:"patientNationalityPeriod,omitempty"`	// extension from https://www.hl7.org/fhir/Patient-extensions.html
	PatientNationalityText		*string	`bson:"patientNationalityText,omitempty" json:"patientNationalityText,omitempty"`	// extension from https://www.hl7.org/fhir/Patient-extensions.html
	PatientNationalityToken		*string	`bson:"patientNationalityToken,omitempty" json:"patientNationalityToken,omitempty"`	// system|code (FHIR API's token format)
}
