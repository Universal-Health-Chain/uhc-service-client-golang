/* Copyright 2021 Fundación UNID */
package authService

import (
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var authController AuthController
func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
	authController = AuthController{models.Service{BackendUrl: backendUrl}}
}

func TestAuthController_Login(t *testing.T) {
	userResp, err := authController.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "error should be nil")
	assert.Equal(t, userResp.Data[0].Username, usernameTesting)
}

func TestAuthController_DeleteUser(t *testing.T) {
	newUser := models.User{Username:"bla4e923la2", Password: "1234", Email: "bla4e393la2@email.com"}
	userResp, err := authController.RegisterUser(newUser)
	assert.Nil(t, err, "error should be nil")
	//assert.Equal(t, userResp.Data[0].Username, newUser.Username)

	userResp, _ = authController.Login(newUser.Username, newUser.Password)
	authController.Token = userResp.Data[0].Token

	deletionReq := models.UserDeletionRequest{Username: newUser.Username, Password: newUser.Password, Email: newUser.Email, DeletionToken: "test"}
	userResp, err = authController.DeleteUser(deletionReq)
	fmt.Println(userResp)

	//assert.Equal(t, userResp.Data[0].Username, newUser.Username)



}


func TestAuthController_RegisterDeletingForTesting(t *testing.T) {

	newUser := models.User{Username:"b4la4e923la2", Password: "1234", Email: "bla4e3593la2@email.com"}

	userResp, _ := authController.RegisterDeletingForTesting(newUser.Username,  newUser.Email,newUser.Password)

	assert.Equal(t, userResp.Username, newUser.Username)



}