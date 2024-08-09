package handlers

import "github.com/go-webauthn/webauthn/protocol"

type MobileCredentialCreationOptions struct {
	AuthenticatorExtensions string                   `json:"authenticatorExtensions"`
	ClientDataHash          string                   `json:"clientDataHash"`
	CredTypesAndPubKeyAlgs  []interface{}            `json:"credTypesAndPubKeyAlgs"`
	ExcludeCredentials      []CredentialDescriptor   `json:"excludeCredentials"`
	RequireResidentKey      bool                     `json:"requireResidentKey"`
	RequireUserPresence     bool                     `json:"requireUserPresence"`
	RequireUserVerification bool                     `json:"requireUserVerification"`
	RP                      MobileRelyingPartyEntity `json:"rp"`
	User                    MobileUserEntity         `json:"user"`
}

type MobileRelyingPartyEntity struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type MobileUserEntity struct {
	Name        string      `json:"name"`
	DisplayName string      `json:"displayName"`
	ID          interface{} `json:"id"`
}

type CredentialDescriptor struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Transports string `json:"transports"`
}

type PasskeyEntry struct {
	CredentialID string `json:"CredentialID"`
	CreatedAt    string `json:"CreatedAt"`
	ImageDark    string `json:"ImageDark"`
	ImageLight   string `json:"ImageLight"`
	AAGUID       string `json:"AAGUID"`
	Description  string `json:"Description"`
	VerMethod    string `json:"VerificationMethod"`
}

type GetAssertionOptions struct {
	RpID                          string                          `json:"rpId"`
	ClientDataHash                string                          `json:"clientDataHash"`
	RequireUserPresence           bool                            `json:"requireUserPresence"`
	RequireUserVerification       bool                            `json:"requireUserVerification"`
	AllowCredentialDescriptorList []protocol.CredentialDescriptor `json:"allowCredentialDescriptorList"`
}

type RegistrationData struct {
	UserID         string `json:"user_id"`
	CredentialID   string `json:"credentialId"`
	AuthData       string `json:"authData"`
	ClientDataHash string `json:"clientDataHash"`
}
