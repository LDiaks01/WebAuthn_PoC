package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"webauthn-example/database"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var wconfig = &webauthn.Config{
	RPDisplayName: "Go Webauthn",                                       // Display Name for your site
	RPID:          "localhost",                                         // Generally the FQDN for your site
	RPOrigins:     []string{"http://localhost:8080", "127.0.0.1:8080"}, // The origin URLs allowed for WebAuthn requests
}

var (
	webAuthn *webauthn.WebAuthn
	err      error
)

// adding this var for the login part
var loginSessionData webauthn.SessionData

var RegistrationChallenge string

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	db := database.InitDB()
	// we get the email from the request
	email := r.FormValue("email")

	// we retrieve the user from the database
	var userFromDb database.User
	if db.Where("email = ?", email).First(&userFromDb).Error != nil {
		fmt.Print("User not found")
		return
	}

	var passkeyUser = DefaultUser{

		ID:          []byte(userFromDb.Email),
		Name:        userFromDb.Username,
		DisplayName: userFromDb.Username,
		//Icon:        "https://example.com/icon.png",
		//Credentials: []webauthn.Credential{}, // Initialisez avec des données par défaut si nécessaire
	}

	if webAuthn, err = webauthn.New(wconfig); err != nil {
		//fmt.Println(err)
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	options, session, err := webAuthn.BeginRegistration(passkeyUser)
	if err != nil {
		fmt.Println(err)

		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	RegistrationChallenge = string(session.Challenge)
	fmt.Println("AllowedCredentialIDs in Begin Registration:", session.AllowedCredentialIDs)
	fmt.Println("Time expires in Begin Registration:", session.Expires)

	JSONResponse(w, options, http.StatusOK) // return the options generated
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {

	db := database.InitDB()
	email := r.FormValue("email")

	var userFromUsers database.User
	if db.Where("email = ?", email).First(&userFromUsers).Error != nil {
		fmt.Print("User not found")
		return
	}

	sessionData10 := webauthn.SessionData{
		Challenge:            RegistrationChallenge,
		UserID:               []byte(email), // "" en base64 décodé
		AllowedCredentialIDs: [][]byte{},    // Vide pour cet exemple
		Expires:              time.Date(0001, time.January, 1, 0, 0, 0, 0, time.UTC),
		UserVerification:     protocol.VerificationPreferred,
	}

	regUser := DefaultUser{
		ID:          []byte(email),
		Name:        userFromUsers.Username,
		DisplayName: userFromUsers.Username,
	}

	c, err := webAuthn.FinishRegistration(regUser, sessionData10, r)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("AllowedCredentialIDs in Begin Registration:", sessionData10.AllowedCredentialIDs)
	fmt.Println("Time expires in Begin Registration:", sessionData10.Expires)
	//then we save the credential in the database
	newPassKeyEntry := database.UserPasskey{
		UserID:          email,
		PublicKey:       c.PublicKey,
		CredentialID:    c.ID,
		AttestationType: c.AttestationType,
		Transport:       joinTransports(c.Transport),
		UserPresent:     c.Flags.UserPresent,
		UserVerified:    c.Flags.UserVerified,
		BackupEligible:  c.Flags.BackupEligible,
		BackupState:     c.Flags.BackupState,
		AAGUID:          c.Authenticator.AAGUID,
		SignCount:       c.Authenticator.SignCount,
		Attachment:      string(c.Authenticator.Attachment),
	}

	db.Create(&newPassKeyEntry)
	//make new credential
	fmt.Println("c in FinishRegistration")
	fmt.Println("ID:", base64.URLEncoding.EncodeToString(c.ID))
	fmt.Println("Public Key:", base64.URLEncoding.EncodeToString(c.PublicKey))
	fmt.Println("Attestation Type:", c.Descriptor().AttestationType)
	fmt.Println("Transport:", c.Descriptor().Transport)
	fmt.Println("Flags:")
	fmt.Println("  User Present:", c.Flags.UserPresent)
	fmt.Println("  User Verified:", c.Flags.UserVerified)
	fmt.Println("  Backup Eligible:", c.Flags.BackupEligible)
	fmt.Println("  Backup State:", c.Flags.BackupState)
	fmt.Println("Authenticator:")
	fmt.Println("  AAGUID:", base64.URLEncoding.EncodeToString(c.Authenticator.AAGUID))
	fmt.Println("  Sign Count:", c.Authenticator.SignCount)
	fmt.Println("  Attachment:", c.Authenticator.Attachment)

	JSONResponse(w, "Registration Success"+c.Descriptor().AttestationType, http.StatusOK)

}

func JSONResponse(w http.ResponseWriter, data interface{}, status int) {
	dj, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	//w.WriteHeader(status)
	fmt.Fprintf(w, "%s", dj)
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		//fmt.Println(err)
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}
	db := database.InitDB()
	email := r.FormValue("email")

	var userFromUsers database.User
	if db.Where("email = ?", email).First(&userFromUsers).Error != nil {
		fmt.Print("User not found")
		return
	}

	var db_passkeys []database.UserPasskey
	if db.Where("user_id = ?", email).Find(&db_passkeys).Error != nil {
		fmt.Print("User not found")
		return
	}

	var userCredentials []webauthn.Credential
	for _, userFromPasskeyUser := range db_passkeys {
		userCredentials = append(userCredentials, webauthn.Credential{
			ID:        userFromPasskeyUser.CredentialID,
			PublicKey: userFromPasskeyUser.PublicKey,
			Authenticator: webauthn.Authenticator{
				AAGUID:     userFromPasskeyUser.AAGUID,
				SignCount:  userFromPasskeyUser.SignCount,
				Attachment: protocol.AuthenticatorAttachment(userFromPasskeyUser.Attachment),
			},
			AttestationType: userFromPasskeyUser.AttestationType,
			Transport:       splitTransports(userFromPasskeyUser.Transport),
			Flags: webauthn.CredentialFlags{
				UserPresent:    userFromPasskeyUser.UserPresent,
				UserVerified:   userFromPasskeyUser.BackupEligible,
				BackupEligible: userFromPasskeyUser.UserVerified,
				BackupState:    userFromPasskeyUser.BackupState,
			},
		})
	}

	// create locally a new credential

	regUser := DefaultUser{
		ID:          []byte(userFromUsers.Email),
		Name:        userFromUsers.Username,
		DisplayName: userFromUsers.Username,
		Credentials: userCredentials,
	}

	options, sessionData, err := webAuthn.BeginLogin(regUser)
	if err != nil {
		fmt.Println(err.Error())
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	loginSessionData = *sessionData
	JSONResponse(w, options, http.StatusOK)

}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	db := database.InitDB()
	email := r.FormValue("email")
	var userFromUsers database.User
	if db.Where("email = ?", email).First(&userFromUsers).Error != nil {
		fmt.Print("User not found")
		return
	}

	var db_passkeys []database.UserPasskey
	if db.Where("user_id = ?", email).Find(&db_passkeys).Error != nil {
		fmt.Print("User not found")
		return
	}
	//create a list of credentials
	var userCredentials []webauthn.Credential
	for _, userFromPasskeyUser := range db_passkeys {
		userCredentials = append(userCredentials, webauthn.Credential{
			ID:        userFromPasskeyUser.CredentialID,
			PublicKey: userFromPasskeyUser.PublicKey,
			Authenticator: webauthn.Authenticator{
				AAGUID:     userFromPasskeyUser.AAGUID,
				SignCount:  userFromPasskeyUser.SignCount,
				Attachment: protocol.AuthenticatorAttachment(userFromPasskeyUser.Attachment),
			},
			AttestationType: userFromPasskeyUser.AttestationType,
			Transport:       splitTransports(userFromPasskeyUser.Transport),
			Flags: webauthn.CredentialFlags{
				UserPresent:    userFromPasskeyUser.UserPresent,
				UserVerified:   userFromPasskeyUser.BackupEligible,
				BackupEligible: userFromPasskeyUser.UserVerified,
				BackupState:    userFromPasskeyUser.BackupState,
			},
		})
	}

	regUser := DefaultUser{
		ID:          []byte(userFromUsers.Email),
		Name:        userFromUsers.Username,
		DisplayName: userFromUsers.Username,
		Credentials: userCredentials,
	}

	credential, err := webAuthn.FinishLogin(regUser, loginSessionData, r)
	fmt.Println("c in FinishLogin")
	fmt.Println("ID:", base64.URLEncoding.EncodeToString(regUser.Credentials[0].ID))
	fmt.Println("Public Key:", base64.URLEncoding.EncodeToString(regUser.Credentials[0].PublicKey))
	fmt.Println("Attestation Type:", regUser.Credentials[0].AttestationType)
	fmt.Println("Transport:", regUser.Credentials[0].Transport)
	fmt.Println("Flags:")
	fmt.Println("  User Present:", regUser.Credentials[0].Flags.UserPresent)
	fmt.Println("  User Verified:", regUser.Credentials[0].Flags.UserVerified)
	fmt.Println("  Backup Eligible:", regUser.Credentials[0].Flags.BackupEligible)
	fmt.Println("  Backup State:", regUser.Credentials[0].Flags.BackupState)
	fmt.Println("Authenticator:")
	fmt.Println("  AAGUID:", base64.URLEncoding.EncodeToString(regUser.Credentials[0].Authenticator.AAGUID))
	fmt.Println("  Sign Count:", regUser.Credentials[0].Authenticator.SignCount)
	fmt.Println("  Attachment:", regUser.Credentials[0].Authenticator.Attachment)
	if err != nil {
		fmt.Println(err)
		JSONResponse(w, "Error LOGIN WebAuthn"+err.Error(), http.StatusInternalServerError)
		return
	}

	print("Login Success : ", base64.URLEncoding.EncodeToString(credential.PublicKey), "\n")

	//create a json entry that contains the username and email
	userResponse := struct {
		Email    string `json:"email"`
		Username string `json:"username"`
	}{Email: userFromUsers.Email,
		Username: userFromUsers.Username,
	}

	//w.Header().Set("Content-Type", "application/json")
	//json.NewEncoder(w).Encode(userResponse)
	//http.Redirect(w, r, "/home?email="+userFromUsers.Email+"&username="+userFromUsers.Username, http.StatusSeeOther)
	JSONResponse(w, userResponse, http.StatusOK)

}

func joinTransports(transports []protocol.AuthenticatorTransport) string {
	transportStrings := make([]string, len(transports))
	for i, transport := range transports {
		transportStrings[i] = string(transport)
	}
	return strings.Join(transportStrings, ",")
}

// Fonction pour convertir une chaîne séparée par des virgules en []protocol.AuthenticatorTransport
func splitTransports(transportStr string) []protocol.AuthenticatorTransport {
	transportStrings := strings.Split(transportStr, ",")
	transports := make([]protocol.AuthenticatorTransport, len(transportStrings))
	for i, transport := range transportStrings {
		transports[i] = protocol.AuthenticatorTransport(transport)
	}
	return transports
}
