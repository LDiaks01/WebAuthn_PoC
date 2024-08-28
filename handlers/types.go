package handlers

import "github.com/go-webauthn/webauthn/protocol"

type MobileCredentialCreationOptions struct {
	AuthenticatorExtensions string                          `json:"authenticatorExtensions"`
	ClientDataHash          string                          `json:"clientDataHash"`
	CredTypesAndPubKeyAlgs  []interface{}                   `json:"credTypesAndPubKeyAlgs"`
	ExcludeCredentials      []protocol.CredentialDescriptor `json:"excludeCredentials"`
	RequireResidentKey      bool                            `json:"requireResidentKey"`
	RequireUserPresence     bool                            `json:"requireUserPresence"`
	RequireUserVerification bool                            `json:"requireUserVerification"`
	RP                      MobileRelyingPartyEntity        `json:"rp"`
	User                    MobileUserEntity                `json:"user"`
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

type PrettyPasskeyEntry struct {
	CredentialID        string `json:"CredentialID"`
	CreatedAt           string `json:"CreatedAt"`
	ImageDark           string `json:"ImageDark"`
	ImageLight          string `json:"ImageLight"`
	AAGUID              string `json:"AAGUID"`
	Description         string `json:"Description"`
	VerMethod           string `json:"VerificationMethod"`
	LastAuthenticatedAt string `json:"LastAuthenticatedAt"`
}

type GetAssertionOptions struct {
	RpID                          string                          `json:"rpId"`
	ClientDataHash                string                          `json:"clientDataHash"`
	RequireUserPresence           bool                            `json:"requireUserPresence"`
	RequireUserVerification       bool                            `json:"requireUserVerification"`
	AllowCredentialDescriptorList []protocol.CredentialDescriptor `json:"allowCredentialDescriptorList"`
}

type BeginMobileRegistrationData struct {
	RelyingPartyID   string                          `json:"relyingPartyId"`
	Challenge        string                          `json:"challenge"`
	Timeout          int                             `json:"timeout"`
	UserVerification string                          `json:"userVerification"`
	AllowCredentials []protocol.CredentialDescriptor `json:"allowCredentials"`
	Mediation        string                          `json:"mediation"`
}

type FinishMobileRegistrationData struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
	ID                string `json:"id"`
	RawID             string `json:"rawId"`
	HashCode          string `json:"hashCode"`
}

type MediationType string

// Définir les constantes pour les types de médiation
const (
	MediationSilent      MediationType = "silent"
	MediationPreferred   MediationType = "preferred"
	MediationConditional MediationType = "conditional"
	MediationOptional    MediationType = "optional"
)

var Transports = []protocol.AuthenticatorTransport{

	protocol.AuthenticatorTransport("usb"),
	protocol.AuthenticatorTransport("nfc"),
	protocol.AuthenticatorTransport("ble"),
	protocol.AuthenticatorTransport("internal"),
	protocol.AuthenticatorTransport("hybrid"),
}
