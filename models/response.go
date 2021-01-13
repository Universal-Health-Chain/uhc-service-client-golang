/* Copyright 2021 Fundación UNID */
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

type DefaultResponseWithDataByte struct {
	Code    int
	Message string
	Data    []byte
}

func (rawJson *DefaultResponseWithDataByte) ReturnCustomResponse(w http.ResponseWriter, code int, customCode int, customMessage string, jsonData *json.RawMessage) {
	var response DefaultResponseWithDataByte

	if jsonData != nil {
		response = DefaultResponseWithDataByte{Code: customCode, Message: customMessage, Data: *jsonData}
	} else {
		response = DefaultResponseWithDataByte{Code: customCode, Message: customMessage, Data: nil}
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(response)
}

