package pawpal

import (
	"crypto/subtle"
	"fmt"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(actualKey, expectedKey []byte, payload any) WebhookVerification {
	if subtle.ConstantTimeCompare(actualKey, expectedKey) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}
	payloadRecord, _ := payload.(map[string]any)
	orderID, _ := payloadRecord["orderId"].(float64)
	status, _ := payloadRecord["status"].(string)
	if orderID == 0 || status != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
