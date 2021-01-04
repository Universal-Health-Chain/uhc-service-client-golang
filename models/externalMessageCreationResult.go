package models

type ExternalMessageCreationResult struct {
	SentMessageUhc       *MessageUHC                `json:"sentMessage,omitempty" bson:"sentMessage,omitempty"`
	CreatedConnectionUhc *ConnectionUHC             `json:"createdConnectionUHC,omitempty" bson:"createdConnectionUHC,omitempty"`
	CreatedUserUhc       *ExternalMessageDirectives `json:"createdUserUhc,omitempty" bson:"createdUserUhc,omitempty"`
}

type ExternalMessageCreationResultResponse struct {
	Code    int                             `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64                           `bson:"count,omitempty" json:"count,omitempty"`
	Message string                          `bson:"message,omitempty" json:"message,omitempty"`
	Data    []ExternalMessageCreationResult `bson:"data,omitempty" json:"data,omitempty"`
}
