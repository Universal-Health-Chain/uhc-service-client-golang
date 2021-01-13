/* Copyright 2021 Fundación UNID */
package authService

const (
	Login                                = "/api/v1/user/login"
	EncryptPayloadUsingEncryptionRequest = "/api/v1/crypto/encrypt"
	GetSharedEncryptionKey               = "/api/v1/crypto/shared/key"

	CreateUserEncryptionKey      = "/api/v1/key/new"
	GetSelfPublicInfoOfActiveKey = "/api/v1/key/public/me"
	GetUserPublicInfoOfActiveKey = "/api/v1/key/public/user/{userId}"
	GetPublicInfoOfEncryptionKey = "/api/v1/key/public/id/{encryptionKeyUserController}"

	CreateOrganizationEncryptionKey      = "/api/v1/organization/uhc/key"
	GetOrganizationPublicInfoOfActiveKey = "/api/v1/organization/uhc/key/public/{organizationId}"

	RegisterUser = "/api/v1/user/register"
	DeleteUser   = "/api/v1/user/me/remove/account"
	FindUser     = "/api/v1/user/info"

	UpdateOrganizationUHCFromVerifyCredential = "/api/v1/organization/uhc/credential"
	CreateOrganizationCredential              = "/api/v1/organization/credential"
	GetOrganizationUHC                        = "/api/v1/organization/uhc"
	GetOrganizationVCByCredentialId           = "/api/v1/organization/credential"
	CreateOrganizationUHCFromFhir             = "/api/v1/organization/uhc/fhir"

	GetOrganizationUHCTokenByToken = "/api/v1/organization/uhc/token/token/{token}"
	GetOrganizationUHCTokenById    = "/api/v1/organization/uhc/token/id/{id}"

	CreateNewUserAndKeyIfNotExists                 = "/api/v1/organization/external/user/register"
	GetOrganizationPublicInfoOfActiveKeyExternally = "/api/v1/organization/external/uhc/key/public/{organizationId}"
	GetUserPublicInfoOfActiveKeyExternally         = "/api/v1/user/external/key/public"
	EncryptPayloadUsingEncryptionRequestExternally = "/api/v1/organization/external/uhc/key/encrypt"

)
