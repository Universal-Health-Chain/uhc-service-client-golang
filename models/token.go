/* Copyright 2021 Fundación UNID */
package models

import (
	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	UserId   string `bson:"userId,omitempty" json:"userId,omitempty"`
	Username string `bson:"username,omitempty" json:"username,omitempty"`
	jwt.StandardClaims
	Role                   []string                 `bson:"role,omitempty" json:"role,omitempty"`
	OrganizationPermission []OrganizationPermission `bson:"organizationPermission,omitempty" json:"organizationPermission,omitempty"`
}
