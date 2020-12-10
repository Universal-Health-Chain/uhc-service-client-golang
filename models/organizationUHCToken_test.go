package models

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAddOrUpdateAccessToService(t *testing.T) {
	token := OrganizationUHCToken{}
	serviceName := "testService"
	role := "ADMIN"
	token.AddOrUpdateAccessToService(serviceName, role)
	assert.Equal(t,token.RoleAccessToService(serviceName), role )

	token = OrganizationUHCToken{}
	permissions := []ApplicationPermission{ApplicationPermission{ServiceName:serviceName, ServiceRole: "1234"}}
	token.ApplicationsPermissions = &permissions

	token.AddOrUpdateAccessToService(serviceName, role)
	assert.Equal(t,token.RoleAccessToService(serviceName), role )

	token = OrganizationUHCToken{}
	permissions = []ApplicationPermission{ApplicationPermission{ServiceName:"1234", ServiceRole: "1234"}}
	token.ApplicationsPermissions = &permissions

	token.AddOrUpdateAccessToService(serviceName, role)
	assert.Equal(t,token.RoleAccessToService(serviceName), role )

	permission, _ := token.GetApplicationPermission(serviceName)
	assert.NotNil(t,&permission.CreatedAt )
	assert.NotNil(t,&permission.ServiceRole, role )





}