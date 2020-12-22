package authService

const (
	Login                                = "/api/v1/user/login"
	EncryptPayloadUsingEncryptionRequest = "/api/v1/crypto/encrypt"
	GetSharedEncryptionKey               = "/api/v1/crypto/shared/key"

	CreateEncryptionKey          = "/api/v1/key/new"
	GetSelfPublicInfoOfActiveKey = "/api/v1/key/public/me"
	GetUserPublicInfoOfActiveKey = "/api/v1/key/public/user/{userId}"
	GetPublicInfoOfEncryptionKey = "/api/v1/key/public/id/{encryptionKey}"

	RegisterUser = "/api/v1/user/register"
	DeleteUser   = "/api/v1/user/me/remove/account"
	FindUser     = "/api/v1/user/info"

	UpdateOrganizationUHCFromVerifyCredential = "/api/v1/organization/uhc/credential"
	CreateOrganizationCredential              = "/api/v1/organization/credential"
	GetOrganizationUHC                        = "/api/v1/organization/uhc"
	GetOrganizationVCByCredentialId           = "/api/v1/organization/credential"

	GetOrganizationUHCTokenByToken = "/api/v1/organization/uhc/token/token/{token}"
	GetOrganizationUHCTokenById    = "/api/v1/organization/uhc/token/id/{id}"
)
