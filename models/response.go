package models

import (
	"encoding/json"
	"net/http"
)

type DefaultResponse struct {
	Code    int
	Message string
	Data    interface{}
	Count   int64
}

type DefaulResponseWithDataByte struct {
	Code    int
	Message string
	Data    []byte
}

func HttpRawJsonResponse(w http.ResponseWriter, code int, customCode int, customMessage string, jsonData *json.RawMessage) {
	var response DefaulResponseWithDataByte

	if jsonData != nil {
		response = DefaulResponseWithDataByte{Code: customCode, Message: customMessage, Data: *jsonData}
	} else {
		response = DefaulResponseWithDataByte{Code: customCode, Message: customMessage, Data: nil}
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(response)
}

func HttpUserResponse(w http.ResponseWriter, code int, customCode int, customMessage string, data *[]User) {
	var response UserResponse
	if data != nil {
		response = UserResponse{Code: customCode, Message: customMessage, Data: *data}
	} else {
		response = UserResponse{Code: customCode, Message: customMessage, Data: nil}
	}
	w.Header().Add("Content-Type", "application/json")

	w.WriteHeader(code)
	json.NewEncoder(w).Encode(response)
}


