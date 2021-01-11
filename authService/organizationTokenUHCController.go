/* Copyright 2021 Fundación UNID */
package authService

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"io/ioutil"
	"net/http"
	"strings"
)

type OrganizationTokenUHCController struct {
	models.Service
}

func (organizationTokenUhcController *OrganizationTokenUHCController) GetOrganizationUHCTokenByToken(token string) (*models.OrganizationUHCTokenResponse, error) {
	tokenResponse := models.OrganizationUHCTokenResponse{}
	url := strings.ReplaceAll(organizationTokenUhcController.BackendUrl + authRoute + GetOrganizationUHCTokenByToken, "{token}", token)

	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", "Bearer "+organizationTokenUhcController.Token)
	request.Header.Set("x-serviceClient-uhc", "organizationTokenUhcController")

	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &tokenResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return &tokenResponse, errors.New(message)
	}
	return &tokenResponse, nil

}


func (organizationTokenUhcController *OrganizationTokenUHCController) GetOrganizationUHCTokenById(id string) (*models.OrganizationUHCTokenResponse, error) {
	tokenResponse := models.OrganizationUHCTokenResponse{}
	url := strings.ReplaceAll(organizationTokenUhcController.BackendUrl + authRoute + GetOrganizationUHCTokenById, "{id}", id)

	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", "Bearer "+organizationTokenUhcController.Token)
	request.Header.Set("x-serviceClient-uhc", "organizationTokenUhcController")

	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &tokenResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return &tokenResponse, errors.New(message)
	}
	return &tokenResponse, nil

}