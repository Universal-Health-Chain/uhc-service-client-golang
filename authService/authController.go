package authService

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"io/ioutil"
	"log"
	"net/http"
)

type AuthController struct {
	models.Service
}

func (authController *AuthController) Login(username string, password string) (*models.UserResponse, error) {
	var userResponse *models.UserResponse
	var user *models.User = &models.User{Username: username, Password: password}
	jsonValue, _ := json.Marshal(user)

	url := authController.BackendUrl + authRoute + Login
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", userAdminController.Token)

	request.Header.Set("x-serviceClient-uhc", "userAdminController")

	client := &http.Client{}
	response, err := client.Do(request)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return nil, errors.New(message)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &userResponse)

	return userResponse, nil

}

func (authController *AuthController) DeleteUser(deletionRequest models.UserDeletionRequest) (*models.UserResponse, error) {
	var userResponse *models.UserResponse
	jsonValue, _ := json.Marshal(deletionRequest)

	url := authController.BackendUrl + authRoute + DeleteUser
	request, _ := http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer " + authController.Token)

	request.Header.Set("x-serviceClient-uhc", "userAdminController")

	client := &http.Client{}
	response, err := client.Do(request)


	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &userResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return userResponse, errors.New(message)
	}


	return userResponse, nil

}


func (authController *AuthController) RegisterUser(user models.User) (*models.UserResponse, error) {
	var userResponse *models.UserResponse
	jsonValue, _ := json.Marshal(user)

	url := authController.BackendUrl + authRoute + RegisterUser
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", userAdminController.Token)

	request.Header.Set("x-serviceClient-uhc", "userAdminController")

	client := &http.Client{}
	response, err := client.Do(request)

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}
	_ = json.Unmarshal(body, &userResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return userResponse, errors.New(message)
	}


	return userResponse, nil

}


func (authController *AuthController) RegisterDeletingForTesting(username, email, password string) (*models.User, error) {
	userResp, err := authController.Login(username,password)
	log.Println("login in to attempt deleting of user")
	if err != nil {
		log.Println("error login in " + err.Error())
	} else {
		deletionReq := models.UserDeletionRequest{Username: username, Password: password, Email: email, DeletionToken: "test"}
		token := userResp.Data[0].Token
		authController.Token = token
		_, err = authController.DeleteUser(deletionReq)
		log.Println("deleting user  if exists")
		if err != nil {
			log.Println("error deleting " + err.Error())
		}
	}

	log.Println("registering to create new user")
	newUser := models.User{Username:username, Password: password, Email: email}

	userResp, err = authController.RegisterUser(newUser)

	if err != nil || userResp == nil || len(userResp.Data)==0 {
		log.Println("error deleting " + err.Error())
		return nil, err
	}

	log.Println("Loging in again to refresh tokens ")
	userResp, err = authController.Login(username,password)

	return &userResp.Data[0], err

}