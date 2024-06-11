package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"webauthn-example/datas"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	webAuthn *webauthn.WebAuthn
	err      error
)

var Challenge_hardened string
var userHardened string

// adding this var for the login part
var loginSessionData webauthn.SessionData

var user = DefaultUser{

	ID:          []byte("Camara"),
	Name:        "Lansana",
	DisplayName: "Lansana_DIARRA",
	//Icon:        "https://example.com/icon.png",
	//Credentials: []webauthn.Credential{}, // Initialisez avec des données par défaut si nécessaire
}

type RequestData struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		AttestationObject string `json:"attestationObject"`
		ClientDataJSON    string `json:"clientDataJSON"`
	} `json:"response"`
	// Ajoutez d'autres champs au besoin
}

// CallWindowsHelloPIN is a handler that handles the registration of a user
func CallWindowsHelloPIN(w http.ResponseWriter, r *http.Request) {
	// Register
	// get the username and password from the form
	username := r.FormValue("username")
	password := r.FormValue("password")

	//send Hello Username
	fmt.Fprintf(w, "Hello %s %s :  this is going to handle the registration with PIN Code", username, password)

}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {

	//fmt.Fprintf(w, "Hello Sirs :  this is going to handle the registration with WebAuthn")
	/*authSelect := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
		RequireResidentKey:      protocol.ResidentKeyNotRequired(),
		UserVerification:        protocol.VerificationRequired,
	}

	// See the struct declarations for values
	conveyancePref := protocol.PreferNoAttestation
	*/
	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn",                                       // Display Name for your site
		RPID:          "localhost",                                         // Generally the FQDN for your site
		RPOrigins:     []string{"http://localhost:8080", "127.0.0.1:8080"}, // The origin URLs allowed for WebAuthn requests
	}

	if webAuthn, err = webauthn.New(wconfig); err != nil {
		//fmt.Println(err)
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	//user := datastore.GetUser() // Find or create the new user I coded this hardly
	options, session, err := webAuthn.BeginRegistration(user)
	//print all the elements of the session ands the options

	//  webauthn.WithAuthenticatorSelection(authSelect), webauthn.WithConveyancePreference(conveyancePref) args supp for the begReg

	// Handle next steps

	//fmt.Println(session)
	// store the sessionData values
	// print everything abut the errors
	if err != nil {
		fmt.Println(err)

		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	datas.SaveSessionData(session)

	Challenge_hardened = session.Challenge
	userHardened = string(session.UserID)
	//fmt.Println(Challenge_hardened)
	//fmt.Println(options.Response.User)
	//fmt.Println(userHardened)
	//print all the elements of the options, their names and their values

	//print(options.Response.Challenge)
	//the pubic key printed

	JSONResponse(w, options, http.StatusOK) // return the options generated
	// options.publicKey contain our registration options
	//FinishRegistration(w, r)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {

	// Get the session data stored from the function above
	//session, erreur := datas.LoadSessionData()
	//print the session data
	//fmt.Println(session)
	//session2 := session[0]

	// test if session is not null and then fetch the 1st element

	/*if erreur != nil {
		fmt.Println(erreur)
	}*/
	//fmt.Println("the final battle")
	sessionData3 := webauthn.SessionData{
		Challenge:            Challenge_hardened,
		UserID:               []byte(userHardened), // "" en base64 décodé
		AllowedCredentialIDs: [][]byte{},           // Vide pour cet exemple
		Expires:              time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
		UserVerification:     protocol.VerificationPreferred,
	}
	/*
		session2 := webauthn.SessionData{
			Challenge:            "ThBV68lT8PmV16orWcd6BwgSlw4dLYw9lEpOuMNGUuU",
			UserID:               []bytebase64.StdEncoding.DecodeString("dW5pcXVlLWlk"),
			AllowedCredentialIDs: [][]byte{},                     // Ajoutez des valeurs si nécessaire
			Expires:              time.Now().Add(24 * time.Hour), // Exemple : 24 heures à partir de maintenant
			UserVerification:     protocol.VerificationPreferred,
			Extensions:           protocol.AuthenticationExtensionsClientInputs{}, // Ajoutez des valeurs si nécessaire
		}
	*/
	//print the headers and the body of the request
	//fmt.Println(r.Header)
	//fmt.Println(r.Body)

	c, err := webAuthn.FinishRegistration(user, sessionData3, r)
	if err != nil {
		// Handle Error and return.
		fmt.Println(err)
		//print the trace of the error
		//fmt.Println("there")
		return
	}

	fmt.Println("ID:", base64.URLEncoding.EncodeToString(c.ID))
	fmt.Println("Public Key:", base64.URLEncoding.EncodeToString(c.PublicKey))
	fmt.Println("Attestation Type:", c.AttestationType)
	fmt.Println("Transport:", c.Transport)
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

	// If creation was successful, store the credential object
	// Pseudocode to add the user credential.

	user.Credentials = append(user.Credentials, *c)
	//fmt.Println(user.Credentials)
	//datastore.SaveUser(user)
	// Print the user informations
	//fmt.Println(user)
	//print to the console the information about the credential
	//fmt.Println(credential)

	// Handle next steps
	/*print(user.ID)
	print(userHardened)
	test := []byte(userHardened)
	print(test)
	*/
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
	//just for being sure
	//user.ID = []byte(userHardened)

	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		fmt.Println(err.Error())
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	loginSessionData = *sessionData
	//datas.SaveSessionData(sessionData)
	//fmt.Println(loginSessionData)
	JSONResponse(w, options, http.StatusOK)

}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	credential, err := webAuthn.FinishLogin(user, loginSessionData, r)
	if err != nil {
		fmt.Println(err)
		JSONResponse(w, "Error LOGIN WebAuthn"+err.Error(), http.StatusInternalServerError)
	}
	print("Login Success : ", credential.PublicKey)
	JSONResponse(w, "Login Success"+credential.Descriptor().AttestationType, http.StatusOK)

}
