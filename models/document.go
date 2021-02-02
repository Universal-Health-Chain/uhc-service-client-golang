package models

import "time"

type Document struct {
	ID               string    `json:"id,omitempty" bson:"id,omitempty"`
	ProfileType      string    `json:"profileType,omitempty" bson:"profileType,omitempty"`
	Title            string    `json:"title,omitempty" bson:"title,omitempty"`
	Description      string    `json:"description,omitempty" bson:"description,omitempty"`
	OriginalFilename string    `json:"originalFilename,omitempty" bson:"originalFilename,omitempty"`
	FileType         string    `json:"fileType,omitempty" bson:"filetType,omitempty"`
	S3Filename       string    `json:"s3Filename,omitempty" bson:"s3Filename,omitempty"`
	TemporaryUrl     string    `json:"temporaryUrl,omitempty" bson:"temporaryUrl,omitempty"`
	Date             time.Time `json:"date,omitempty" bson:"date,omitempty"`
	LastUpdated      time.Time `json:"lastUpdated,omitempty" bson:"lastUpdated,omitempty"`
}

type DocumentResponse struct {
	Code    int        `json:"code,omitempty" bson:"code,omitempty"`
	Message string     `json:"message,omitempty" bson:"message,omitempty"`
	Data    []Document `json:"data,omitempty" bson:"data,omitempty"`
	Count   int64      `json:"count,omitempty" bson:"count,omitempty"`
}
