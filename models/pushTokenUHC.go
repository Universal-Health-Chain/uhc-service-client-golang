package models

import "time"

type UserTokensUHC struct {
	UhcID      string      `json:"uhcId,omitempty" bson:"uhcId,omitempty"`
	PushTokens []PushToken `json:"pushTokens,omitempty" bson:"pushTokens,omitempty"`
}
type PushToken struct {
	Token        string    `json:"token,omitempty" bson:"token,omitempty"`
	Os           string    `json:"os,omitempty" bson:"os,omitempty"`
	RegisterDate time.Time `json:"registerDate,omitempty" bson:"registerDate,omitempty"`
}
type PushTokensUHCResponse struct {
	Code         int             `json:"code,omitempty" bson:"code,omitempty"`
	Message      string          `json:"message,omitempty" bson:"message,omitempty"`
	DataResponse []UserTokensUHC `json:"data,omitempty" bson:"data,omitempty"`
	Count        int64           `json:"count,omitempty" bson:"count,omitempty"`
}
