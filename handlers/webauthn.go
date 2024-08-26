package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/LDiaks01/WebAuthn_PoC/database"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"
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

// handle the deletion of a credential
func DeleteCredentialHandler(w http.ResponseWriter, r *http.Request) {
	db := database.InitDB()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	credentialId := string(body)

	// Find and delete the credential
	var credential database.UserPasskey
	bytes_cred, err := base64.RawStdEncoding.DecodeString(credentialId)
	if err != nil {
		http.Error(w, "Failed to decode credential ID", http.StatusInternalServerError)
		return
	}

	if err := db.Where("credential_id = ?", bytes_cred).First(&credential).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "Credential not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to retrieve credential", http.StatusInternalServerError)
		}
		return
	}

	if err := db.Delete(&credential).Error; err != nil {
		http.Error(w, "Failed to delete credential", http.StatusInternalServerError)
		return
	}

	// Respond with success
	JSONResponse(w, "Credential deleted successfully", http.StatusOK)

}
