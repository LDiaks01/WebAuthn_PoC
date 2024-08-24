package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/LDiaks01/WebAuthn_PoC/database"
	"github.com/go-webauthn/webauthn/webauthn"
)

func BeginMobileLogin(w http.ResponseWriter, r *http.Request) {
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		//fmt.Println(err)
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	db := database.InitDB()

	// we get the email from the request JSON body
	type RequestEmailBody struct {
		Email string `json:"email"`
	}
	var emailBody RequestEmailBody

	err := json.NewDecoder(r.Body).Decode(&emailBody)
	// Décoder le JSON à partir du corps de la requête
	if err != nil {
		//http.Error(w, "Error decoding JSON content, verify the JSON Format"+err.Error(), http.StatusBadRequest)
		fmt.Println("Error decoding JSON:", err)
		JSONResponse(w, "Error decoding JSON content, verify the JSON Format"+err.Error(), http.StatusBadRequest)
		return
	}
	if emailBody.Email == "" {
		JSONResponse(w, "Email field is empty", http.StatusBadRequest)
		return
	}

	// we retrieve the user from the database
	// the db where gorm is secure against SQL injection
	var userFromDb database.User
	if db.Where("email = ?", emailBody.Email).First(&userFromDb).Error != nil {
		fmt.Print("User not found")
		JSONResponse(w, "Email not found", http.StatusBadRequest)
		return
	}

	//credentialList := retrieveUserCredsAsMobileDescriptor(emailBody.Email)
	credentialListForBeginLogin := retrieveUserCredsAsCredentialList(emailBody.Email)
	regUser := DefaultUser{
		ID:          []byte(userFromDb.Email),
		Name:        userFromDb.Username,
		DisplayName: userFromDb.Username,
		Credentials: credentialListForBeginLogin,
	}

	credentialListForClient := retrieveUserCredsAsMobileDescriptor(emailBody.Email)

	options, sessionData, err := webAuthn.BeginLogin(regUser)
	if err != nil {
		fmt.Println(err.Error())
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	LoginChallenge = sessionData.Challenge
	LoginUserEmail = emailBody.Email

	optionsToClient := BeginMobileRegistrationData{
		RelyingPartyID:   webAuthn.Config.RPID,
		Challenge:        options.Response.Challenge.String(), // String() call RawBase64URL() method, all others encoding are Base64URL
		Timeout:          options.Response.Timeout,
		UserVerification: string(webAuthn.Config.AuthenticatorSelection.UserVerification),
		AllowCredentials: credentialListForClient,
		Mediation:        string(MediationConditional),
	}

	JSONResponse(w, optionsToClient, http.StatusOK)

}

func FinishMobileLogin(w http.ResponseWriter, r *http.Request) {
	if LoginUserEmail == "" {
		fmt.Println("Error : Follow the required steps : The user email is empty, so no beginning of login")
		JSONResponse(w, "Error : Follow the required steps", http.StatusBadRequest)
	}

	db := database.InitDB()

	var userFromUsers database.User
	if db.Where("email = ?", LoginUserEmail).First(&userFromUsers).Error != nil {
		fmt.Print("User not found")
		return
	}

	var db_passkeys []database.UserPasskey
	if db.Where("user_id = ?", LoginUserEmail).Find(&db_passkeys).Error != nil {
		fmt.Print("User not found")
		return
	}

	regUser := DefaultUser{
		ID:          []byte(LoginUserEmail),
		Name:        userFromUsers.Username,
		DisplayName: userFromUsers.Username,
		Credentials: retrieveUserCredsAsCredentialList(LoginUserEmail),
	}

	// create a session data object and fill it with the challenge from the begin login
	loginSessionData := webauthn.SessionData{
		Challenge: LoginChallenge,
		UserID:    []byte(LoginUserEmail),
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
