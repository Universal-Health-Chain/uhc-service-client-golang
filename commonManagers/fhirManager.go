package commonManagers

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/google/uuid"
)

func UhcMessageByFhirMessage(fhirMessageEncryptedBase64, recipientUhcUserId, userId string) (uhcMessage *models.MessageUHC){

	id, _ := uuid.NewRandom()
	idStr := id.String()	// uhcMessage.ID = id.String() fails
	messageUHC := models.MessageUHC{
		ToUserId:   recipientUhcUserId,
		FromUserId: userId,
		ID: idStr,			// id.String() fails
		Status : "UNREAD",
		UHCPayload: &models.UHCPayload{
			PayloadBase64: fhirMessageEncryptedBase64,
			EncryptedPayload: true,
		},
	}
	return &messageUHC
}
