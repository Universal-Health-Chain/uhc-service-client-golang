/* Copyright 2021 Fundación UNID */
package models

const HeaderUHC = "x-uhc-"
const HeaderFHIR = "x-fhir-"
const HL7CodeSystemSNOMED = "http://snomed.info/sct"
const HL7CodeSystemLOINC = "http://loinc.org"

const (
	// From distinct API resources
	FhirApiAuthenticator		= "authenticator"	// Who/what has authenticated the data
	FhirApiAuthor				= "author"			// Who/what has authored the data
	FhirApiOrganizationCustodian= "custodian"		// Organization which maintains the data
	FhirApiSubject         		= "subject"			// Who/what is the subject data relates to
	FhirApiOrganization			= "organization"	// The organization custodian or responsible
	FhirApiManufacturer			= "manufacturer"	// Who manufacture
	FhirApiPerformer			= "performer"		// Who performs
	FhirApiAsserter				= "asserter"		// Source of the information
	FHirApiRecorder				= "recorder"		// Who recorder
	FhirApiDevice 				= "device"			// Device identifier

	// DocumentReference
	FhirApiCategory 			= "category"			// IPS / USCDI section (High-level kind of clinical document) e.g. "11369-6" (History of Immunization)
	FhirApiMimeContentType   	= "contenttype"  		// e.g. application/pdf
	FhirApiDate            		= "date"				// When the FHIR resource was created in ISO format (FHIR dateTime)
	FhirApiDescription 			= "description"			// Human-readable description
	FhirApiEncounter 			= "encounter"			// Context of the document content
	FhirApiEvent 				= "event"				// Main clinical acts documented
	FhirApiFacilityType			= "facility"			// Kind of facility where subject was seen
	FhirApiFormatCodeSet   		= "format"				// Format/content rules for the document e.g. "urn:ihe:pcc:xphr:2007" or "urn:ihe:pcc:ic:2008"
	FhirApiIdentifier			= "identifier"			// Master Version Specific Identifier
	FhirApiLanguage				= "language"			// Language of the FHIR resource
	FhirApiLocation				= "location"			// URI where the data can be found
	FhirApiPeriod    			= "period"				// FHIR dateTime: time of service that is being documented
	FhirApiRelated				= "related"
	FhirApiRelatesTo			= "relatesto"
	FhirApiRelation				= "relation"
	FhirApiRelationShip			= "relationship"
	FhirApiSecurityLabel		= "security-label"
	FhirApiPracticeSetting		= "setting"				// Clinical Specialty: additional details about where the content was created (e.g. clinical specialty)
	FhirApiStatus            	= "status"				// Current status (accepted values depends on each specific FHIR resource)

	// Procedure
	FhirApiBasedOn				= "based-on"
	FhirApiCode 				= "code"
	FhirApiInstantiatesCanonical= "instantiates-canonical"
	FhirApiInstantiatesUri 		= "instantiates-uri"
	FhirApiPartOf 				= "part-of"
	FhirApiReasonCode			= "reason-code"			// Why occurred the healthcare process
	FhirApiReasonReference		= "reason-reference"

	// Device
	FhirApiModel 				= "model"
	FhirApiType            		= "type"				// Type for device, also for additional more precise type of document ...
	FhirApiDeviceUdiCarrierHRF	= "udi-carrier"			// UDI Barcode (RFID or other technology) string in *HRF* format
	FhirApiDeviceUdiDI			= "udi-di"				// The udi Device Identifier (DI)
	FhirApiURL 					= "url"					// Network address to contact device

	// Immunization
	FhirApiLotNumber			= "lot-number"			// Vaccine lot number.
	FhirApiReaction 			= "reaction"			// Observation with details on reaction
	FhirApiReactionDate 		= "reaction-date"		// Both for immunization and for allergies and intolerances
	FhirStatusReason			= "status-reason"		// Not done reason code
	FhirTargetDisease			= "target-disease"		// Target disease.

	// Allergies and intolerances
	FhirApiClinicalStatus		= "clinical-status"
	FhirApiCritically 			= "critically"
	FhirApiOccurrenceLastDate 	= "last-date"
	FhirApiReactionManifestation= "manifestation"
	FhirApiReactionOnset 		= "onset"
	FhirApiRoute          		= "route"				// Path of substance
	FhirApiSeverity				= "severity"
	FhirApiVerificationStatus 	= "verification-status"

	// MedicationAdministration
	FhirApiContext				= "context"				// reference to episode of care or encounter
	FhirApiEffectiveTime 		= "effective-time"
	FhirApiMedication 			= "medication"
	FhirApiReasonGiven 			= "reason-given"
	FhirApiReasonNotGiven 		= "reason-not-given"
	FhirApiRequest				= "request"
)

const (
	UhcApiConnection 			= "connection"			// ID of an existing UHC connection
	UhcApiTextTile         		= "text-title"			// Title in plain text filed by a practitioner or device (no xhtml)
	UhcApiDocStatus         	= "docstatus"			// e.g. "final", "preliminary", "amended", "entered-in-error"
	UhcApiSHA1Hex           	= "sha1-hex"			// Legacy SHA1 digest in hexadecimal (FHIR Attachment Hash is Base64 SHA1,not Hex)
	UhcApiBytesSize             = "size"				// Number of bytes of content
	UhcApiCreationDateTime  	= "creation"			// When the attached file or message was created (distinct from FhirApiDate for FHIR resources)
	UhcApiVaccineCodeCVX		= "vaccine-cvx"			// Vaccine Administered  CVX code.
	UhcApiDoseNumber           	= "dose-number"			// Dose number within series.
	UhcApiDosesRecommended		= "doses-recommended"	// Recommended number of doses for immunity.
	UhcApiExpirationDate       	= "expiration"			// FHIR dateTime of expiration
	UhcApiDoseQuantity         	= "dose-quantity"		// Amount of dose and international unit separated by "|" e.g.: 1|mL
	UhcApiSiteBody        		= "site"				// Body site
	UhcApiAdministrationMethod 	= "method"				// How drug was administered
	UhcApiRateRatioNumerator 	= "ratio-numerator"		// Numerator value with international unit separated by "|" e.g.: 1|mL
	UhcApiRateRatioDenominator 	= "ratio-denominator"	// Denominator value with international unit separated by "|" e.g.: 1|mL
	UhcApiRateQuantity 			= "rate-quantity"		// Dose quantity per unit of time with international unit separated by "|" e.g.: 1|mL
)

