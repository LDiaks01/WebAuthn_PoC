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
	RPDisplayName:         "Go Webauthn",                                       // Display Name for your site
	RPID:                  "localhost",                                         // Generally the FQDN for your site
	RPOrigins:             []string{"http://localhost:8080", "127.0.0.1:8080"}, // The origin URLs allowed for WebAuthn requests
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
		//AuthenticatorAttachment: protocol.AuthenticatorAttachment("cross-platform"),
		//RequireResidentKey: protocol.ResidentKeyNotRequired(),
		UserVerification: protocol.VerificationDiscouraged,
	},
	//the direct and indirect way give a good aaguid

}

var (
	webAuthn *webauthn.WebAuthn
	err      error
)

// the two challenges need to persist between the two handlers
var RegistrationChallenge string
var LoginChallenge string

func BeginMobileRegistration(w http.ResponseWriter, r *http.Request) {
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		//fmt.Println(err)
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	db := database.InitDB()
	// we get the email from the request
	var email string

	err := json.NewDecoder(r.Body).Decode(&email)
	// Décoder le JSON à partir du corps de la requête
	if err != nil {
		http.Error(w, "Error decoding JSON content"+err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Android printing  email:", email)
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
		//Credentials: retrieveUserCredentials(email), // No more need to do it here, it's done in the BeginRegistration function
	}

	/* for selecting the authenticator
	authSelect := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
		RequireResidentKey: protocol.ResidentKeyNotRequired(),
		UserVerification: protocol.VerificationRequired,
	}
	*/

	options, session, err := webAuthn.BeginRegistration(passkeyUser, webauthn.WithExclusions(retrieveUserCredsAsMobileDescriptor(email)))
	if err != nil {
		fmt.Println(err)

		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	RegistrationChallenge = string(session.Challenge)
	var sentOptions = mobileCredentialOptionBuilder(options.Response)
	fmt.Println(sentOptions)

	JSONResponse(w, sentOptions, http.StatusOK) // return the options generated
}

func FinishMobileRegistration(w http.ResponseWriter, r *http.Request) {

	db := database.InitDB()

	var data RegistrationData

	// Retrieve the JSON data from the request
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&data)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		http.Error(w, "Error decoding JSON"+err.Error(), http.StatusBadRequest)
		return
	}

	var userFromUsers database.User
	if db.Where("email = ?", data.UserID).First(&userFromUsers).Error != nil {
		fmt.Print("User not found")
		return
	}

	/*
		regSessionData := webauthn.SessionData{
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

		c, err := webAuthn.FinishRegistration(regUser, regSessionData, r)
		if err != nil {
			fmt.Println(err)
			return
		}

		//print the user ID base64url
		fmt.Println("User ID:", base64.URLEncoding.EncodeToString(regUser.ID))
	*/
	//then we save the credential in the database,
	// the obligatories are just pb_key, user_id, credential_id,
	// the rest is optional
	newPassKeyEntry := database.UserPasskey{
		UserID:         data.UserID,
		CredentialID:   data.CredentialID,
		Attachment:     data.AuthData,
		ClientDataHash: data.ClientDataHash,
	}

	errv := db.Create(&newPassKeyEntry)
	if errv.Error != nil {
		fmt.Println("Error creating passkey entry:", errv.Error)
		return
	}
	//credConsoleLogger(c)
	fmt.Println("Registration Success")

	JSONResponse(w, "Registration Success", http.StatusCreated)

}

// function that return a JSON response
func JSONResponse(w http.ResponseWriter, data interface{}, status int) {
	dj, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	//w.WriteHeader(status)
	fmt.Fprintf(w, "%s", dj)
}

func MobileLogin(w http.ResponseWriter, r *http.Request) {
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		//fmt.Println(err)
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	db := database.InitDB()
	// we get the email from the request
	var email string

	err := json.NewDecoder(r.Body).Decode(&email)
	// Décoder le JSON à partir du corps de la requête
	if err != nil {
		http.Error(w, "Error decoding JSON content"+err.Error(), http.StatusBadRequest)
		return
	}

	// We need to build the response in a required json format
	credentialList := retrieveUserCredsAsMobileDescriptor(email)
	// search the email in users_table first
	var userFromUsers database.User
	if db.Where("email = ?", email).First(&userFromUsers).Error != nil {
		fmt.Print("User not exist")
		http.Error(w, "User does not exist", http.StatusBadRequest)
		return
	}

	// then in passkeys_table
	var db_passkeys []database.UserPasskey
	if db.Where("user_id = ?", email).Find(&db_passkeys).Error != nil {
		fmt.Print("User has no passkey")
		return
	}
	// test if db_passkeys is empty
	if len(db_passkeys) == 0 {
		fmt.Print("User has no passkey")
		return
	}

	// The get Assertion options is the type that will be sent to the client
	var assertionOption GetAssertionOptions
	assertionOption.ClientDataHash = db_passkeys[0].ClientDataHash
	assertionOption.RpID = "localhost"
	assertionOption.RequireUserPresence = true
	assertionOption.RequireUserVerification = false
	assertionOption.AllowCredentialDescriptorList = credentialList

	fmt.Println("Assertion Option:", assertionOption)
	JSONResponse(w, assertionOption, http.StatusOK)

	/*
		regUser := DefaultUser{
			ID:          []byte(userFromUsers.Email),
			Name:        userFromUsers.Username,
			DisplayName: userFromUsers.Username,
			Credentials: retrieveUserCredsAsCredentialList(email),
		}

		options, sessionData, err := webAuthn.BeginLogin(regUser)
		if err != nil {
			fmt.Println(err.Error())
			JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
		}

		LoginChallenge = sessionData.Challenge
		JSONResponse(w, options, http.StatusOK)
	*/

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

	regUser := DefaultUser{
		ID:          []byte(userFromUsers.Email),
		Name:        userFromUsers.Username,
		DisplayName: userFromUsers.Username,
		Credentials: retrieveUserCredsAsCredentialList(email),
	}

	// create a session data object and fill it with the challenge from the begin login
	loginSessionData := webauthn.SessionData{
		Challenge: LoginChallenge,
		UserID:    []byte(email),
	}

	credential, err := webAuthn.FinishLogin(regUser, loginSessionData, r)
	//fmt.Println("c in FinishLogin :")
	//credConsoleLogger(credential)
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
