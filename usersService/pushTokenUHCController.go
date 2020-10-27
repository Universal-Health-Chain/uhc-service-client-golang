package usersService

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/service"
	"io/ioutil"
	"net/http"
	_ "os"
)

type PushTokenUHCController struct {
	service.Service
}

const usersRoute = "/users-service"

func (pushTokenController *PushTokenUHCController) GetPushTokensByUHCId(uhcId string) (pushTokenResponse *models.PushTokensUHCResponse, err error) {

	url := pushTokenController.BackendUrl + usersRoute + GetPushTokensByUHCId + "/" + uhcId
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+pushTokenController.Token)

	request.Header.Set("x-service-uhc", "pushTokenController")

	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return nil, errors.New(message)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &pushTokenResponse)

	return pushTokenResponse, nil

}
