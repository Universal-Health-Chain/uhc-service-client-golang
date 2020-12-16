package models

import (
	"errors"
	"time"
)

const (
	OrganizationUHCAccessNONE  = "NONE"
	OrganizationUHCAccessADMIN = "ADMIN"
)

const (
	OrganizationUHCStatusINACTIVE  = "INACTIVE"
	OrganizationUHCStatusADMIN = "ACTIVE"
)

type OrganizationUHCToken struct {
	ID                      string                   `json:"id,omitempty" bson:"id,omitempty"`
	DeviceId                string                   `json:"deviceId,omitempty" bson:"deviceId,omitempty"`
	Token                   string                   `json:"token,omitempty" bson:"token,omitempty"`
	OrganizationOwnerId     string                   `json:"organizationOwnerId,omitempty" bson:"organizationOwnerId,omitempty"`
	ApplicationsPermissions *[]ApplicationPermission `bson:"applicationsPermissions,omitempty" json:"applicationsPermissions,omitempty"`
	CreatedAt               *time.Time               `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt               *time.Time               `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
	Status               	string             		 `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
}

type OrganizationUHCTokenResponse struct {
	Code    int          `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64        `bson:"count,omitempty" json:"count,omitempty"`
	Message string       `bson:"message,omitempty" json:"message,omitempty"`
	Data    []OrganizationUHCToken `bson:"data,omitempty" json:"data,omitempty"`
}

func (organizationUhcToken *OrganizationUHCToken) RoleAccessToService(serviceName string) string {
	if organizationUhcToken.ApplicationsPermissions == nil {
		return OrganizationUHCAccessNONE
	} else {
		for _, permission := range *organizationUhcToken.ApplicationsPermissions {
			if permission.ServiceName == serviceName {
				return permission.ServiceRole
			}
		}
	}
	return OrganizationUHCAccessNONE
}

func (organizationUhcToken *OrganizationUHCToken) GetApplicationPermission(serviceName string) (*ApplicationPermission, error) {
	if organizationUhcToken.ApplicationsPermissions == nil {
		return nil, errors.New("no permissions for this token")
	} else {
		for _, permission := range *organizationUhcToken.ApplicationsPermissions {
			if permission.ServiceName == serviceName {
				return &permission, nil
			}
		}
	}
	return nil, errors.New("no permissions for this service")

}

func (organizationUhcToken *OrganizationUHCToken) AddOrUpdateAccessToService(serviceName string, role string) {
	if organizationUhcToken.ApplicationsPermissions == nil {
		created := time.Now()
		newPermission := ApplicationPermission{ServiceRole: role, ServiceName: serviceName, CreatedAt: &created}
		organizationUhcToken.ApplicationsPermissions = &[]ApplicationPermission{newPermission}
	} else {
		for index, permission := range *organizationUhcToken.ApplicationsPermissions {
			if permission.ServiceName == serviceName {
				permissions := *organizationUhcToken.ApplicationsPermissions
				permissions[index].ServiceRole = role
				organizationUhcToken.ApplicationsPermissions = &permissions
				break
			}
		}
	}
	created := time.Now()
	newPermission := ApplicationPermission{ServiceRole: role, ServiceName: serviceName, CreatedAt: &created}
	permissions := append(*organizationUhcToken.ApplicationsPermissions, newPermission)
	organizationUhcToken.ApplicationsPermissions = &permissions
}
