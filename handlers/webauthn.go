package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var wconfig = &webauthn.Config{
	RPDisplayName: "HATA Mobile Passkeys Test", // Display Name for your site
	RPID:          "passkey.hata.io",           // Generally the FQDN for your site
	RPOrigins: []string{"passkey.hata.io", "passkey.hata.io/", "https://passkey.hata.io",
		"https://passkey.hata.io/", "http://passkey.hata.io", "http://passkey.hata.io/",
		"android:apk-key-hash:LNbiYblBNnGCy6kYW99g8ZDt0zgV2Em8igUYBd77QrE=",
		"android:apk-key-hash:LNbiYblBNnGCy6kYW99g8ZDt0zgV2Em8igUYBd77QrE"}, // The origin URLs allowed for WebAuthn requests
	AttestationPreference: protocol.PreferIndirectAttestation,
	// Timeout values for the registration and authentication processes
	Timeouts: webauthn.TimeoutsConfig{
		Login: webauthn.TimeoutConfig{
			Enforce:    true,
			Timeout:    3 * time.Minute,
			TimeoutUVD: 3 * time.Minute,
		},
		Registration: webauthn.TimeoutConfig{
			Enforce:    true,
			Timeout:    3 * time.Minute,
			TimeoutUVD: 3 * time.Minute,
		},
	},
	// See the struct declarations for values
	AuthenticatorSelection: protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
		RequireResidentKey:      protocol.ResidentKeyRequired(),
		UserVerification:        protocol.VerificationRequired,
		ResidentKey:             protocol.ResidentKeyRequirement("required"),
	},
	//the direct and indirect way give a good aaguid

}

var (
	webAuthn *webauthn.WebAuthn
	err      error
)

// function that return a JSON response
func JSONResponse(w http.ResponseWriter, data interface{}, status int) {
	dj, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(status)
	fmt.Fprintf(w, "%s", dj)
}
