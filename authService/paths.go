package authService

const (
	Login                                = "/api/v1/user/login"
	EncryptPayloadUsingEncryptionRequest = "/api/v1/crypto/encrypt"
	GetSharedEncryptionKey               = "/api/v1/crypto/shared/key"

	CreateEncryptionKey                  = "/api/v1/key/new"
	GetSelfPublicInfoOfActiveKey         = "/api/v1/key/public/me"
	GetUserPublicInfoOfActiveKey         = "/api/v1/key/public/user/{userId}"
	GetPublicInfoOfEncryptionKey         = "/api/v1/key/public/id/{encryptionKey}"

	RegisterUser                         = "/api/v1/user/register"
	DeleteUser                           = "/api/v1/user/me/remove/account"
	FindUser                             = "/api/v1/user/info"

)
