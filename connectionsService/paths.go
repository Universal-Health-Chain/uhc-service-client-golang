package connectionsService

const (
	GetConnectionUHCById                  = "/api/v1/connection/uhc/id/{connectionId}"
	CreateConnectionUHCImplicitInvitation = "/api/v1/connection/uhc/implicit"
	SendMessageUhc                        = "/api/v1/message/uhc/send"
	CreateConnectionUHCExternally         = "/api/v1/external/connection/uhc"
	SendMessageUhcExternally              = "/api/v1/external/message/uhc/send"
)
