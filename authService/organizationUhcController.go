package authService

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	fhir4 "github.com/Universal-Health-Chain/golang-fhir-models-uhc/fhir-models/fhir"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"io/ioutil"
	"net/http"
)

type OrganizationUHCController struct {
	models.Service
}

func (organizationUHCController *OrganizationUHCController) CreateOrganizationUHCFromFhir(organizationFhir fhir4.Organization) (*models.OrganizationVCResponse, error) {

	jsonValue, _ := json.Marshal(organizationFhir)
	organizationUhcResponse := models.OrganizationVCResponse{}
	url := organizationUHCController.BackendUrl + authRoute + CreateOrganizationUHCFromFhir
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+organizationUHCController.Token)
	request.Header.Set("x-serviceClient-uhc", "organizationUHCController")

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

	_ = json.Unmarshal(body, &organizationUhcResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return &organizationUhcResponse, errors.New(message)
	}

	return &organizationUhcResponse, nil
}


func (organizationUHCController *OrganizationUHCController) GetOrganizationUHC(organizationUhcId string) (*models.OrganizationUHCResponse, error) {

	organizationUhcResponse := models.OrganizationUHCResponse{}
	url := organizationUHCController.BackendUrl + authRoute + GetOrganizationUHC + "?organizationId=" + organizationUhcId

	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+organizationUHCController.Token)
	request.Header.Set("x-serviceClient-uhc", "OrganizationUHCController")

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

	_ = json.Unmarshal(body, &organizationUhcResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return &organizationUhcResponse, errors.New(message)
	}

	return &organizationUhcResponse, nil
}