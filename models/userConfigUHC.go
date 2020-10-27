package models

import (
	"time"
)

type UserConfigUHC struct {
	Type                       string                      `json:"type,omitempty" bson:"type,omitempty"`
	UhcID                      string                      `json:"uhcId,omitempty" bson:"uhcId,omitempty"`
	BlockchainID               string                      `json:"blockchainUserId,omitempty" bson:"blockchainUserId,omitempty"`
	ExternalIDs                []UserExternalID            `json:"externalIds,omitempty" bson:"externalIds,omitempty"`
	FavoriteLocationUHCIDs     []string                    `json:"favoriteLocationUhcIds,omitempty" bson:"favoriteLocationUhcIds,omitempty"`
	AcceptedTermsAndConditions []AcceptedTermsAndCondition `json:"acceptedTermsAndConditions,omitempty" bson:"acceptedTermsAndConditions,omitempty"`
	Ratings                    []Rate                      `json:"ratings,omitempty" bson:"ratings,omitempty"`
	UserContacts               []UserContact               `json:"userContacts,omitempty" bson:"userContacts,omitempty"`
}

type UserContact struct {
	UserUhcId string `json:"userUhcId,omitempty" bson:"userUhcId,omitempty"`
	Tag       string `json:"tag,omitempty" bson:"tag,omitempty"`
}

type UserContactComplete struct {
	User User   `bson:"user,omitempty" json:"user,omitempty"`
	Tag  string `bson:"tag,omitempty" json:"tag,omitempty"`
}

type Rate struct {
	RateDate   time.Time `json:"rateDate,omitempty" bson:"rateDate,omitempty"`
	Stars      int       `json:"stars,omitempty" bson:"stars,omitempty"`
	Suggestion string    `json:"suggestion,omitempty" bson:"suggestion,omitempty"`
	AppId      string    `json:"appId,omitempty" bson:"appId,omitempty"`
}

type AcceptedTermsAndCondition struct {
	TermsAndConditionsId string    `json:"termsAndConditionsId,omitempty" bson:"termsAndConditionsId,omitempty"`
	AcceptedDate         time.Time `json:"acceptedDate,omitempty" bson:"acceptedDate,omitempty"`
}

type UserExternalID struct {
	Type    string `json:"type,omitempty" bson:"type,omitempty"`       //public or pairwise
	Profile string `json:"profile,omitempty" bson:"profile,omitempty"` //health, education...
	UUID    string `json:"uuid,omitempty" bson:"uuid,omitempty"`
}

type UserConfigUHCResponse struct {
	Code         int             `json:"code,omitempty" bson:"code,omitempty"`
	Message      string          `json:"message,omitempty" bson:"message,omitempty"`
	DataResponse []UserConfigUHC `json:"data,omitempty" bson:"data,omitempty"`
	Count        int64           `json:"count,omitempty" bson:"count,omitempty"`
}

type UserContactsResponse struct {
	Code         int                   `json:"code,omitempty" bson:"code,omitempty"`
	Message      string                `json:"message,omitempty" bson:"message,omitempty"`
	DataResponse []UserContactComplete `json:"data,omitempty" bson:"data,omitempty"`
	Count        int64                 `json:"count,omitempty" bson:"count,omitempty"`
}
