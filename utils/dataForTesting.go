package utils

import (
	"encoding/json"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"io/ioutil"
	"log"
	"strings"
)

var encryptionKeysExamplesFilesPath = "../utils/dataForTesting/encryptionKey"

var encryptionKeysExamples = []models.Key{}


func GetEncryptionKeysForTesting() (users []models.Key, err error) {
	if len(encryptionKeysExamples) == 0 {
		root := encryptionKeysExamplesFilesPath
		files, _ := ioutil.ReadDir(root)
		for _, f := range files {
			// check if it is a right file (and not .DSStore for example)
			if strings.Contains(f.Name(), ".json") {
				encryptionKey, err := readEncryptionKeysInJson(root + "/" + f.Name())
				if err != nil {
					log.Println(err)
					return encryptionKeysExamples, err
				}
				encryptionKeysExamples = append(encryptionKeysExamples, encryptionKey)
			}
		}
	}

	return encryptionKeysExamples, nil
}



func readEncryptionKeysInJson(path string) (organizations models.Key, err error) {
	encryptionKey := models.Key{}
	result, err1 := ioutil.ReadFile(path)
	if err1 != nil {
		log.Println(err1)
		return models.Key{}, err1 //empty and error
	}
	err2 := json.Unmarshal([]byte(result), &encryptionKey)
	if err2 != nil {
		log.Println(err2)
		return models.Key{}, err2 //empty and error
	}
	return encryptionKey, nil

}
