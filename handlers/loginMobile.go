package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/LDiaks01/WebAuthn_PoC/database"
	"github.com/go-webauthn/webauthn/webauthn"
)

func BeginMobileLogin(w http.ResponseWriter, r *http.Request) {
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		//fmt.Println(err)
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	db := database.InitDB()
	rdb := database.InitRedis()

	ctx, cancelContext := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelContext()

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
		return
	}

	var tempLogData = []string{emailBody.Email, string(sessionData.Challenge)}
	tempLogDataSerialized, err := json.Marshal(tempLogData)
	if err != nil {
		log.Fatalf("could not marshal data: %v", err)
		JSONResponse(w, "An error occured", http.StatusInternalServerError)
		return
	}

	tempLogDataKey := GenerateUUID()
	_, err = rdb.Set(ctx, tempLogDataKey, tempLogDataSerialized, database.RedisExpirationDuration).Result()
	if err != nil {
		fmt.Println("Error storing registration data in redis:", err)
		JSONResponse(w, "An error occured", http.StatusInternalServerError)
		return
	}

	// add the key to the http cookie
	cookie := http.Cookie{
		Name:     "logDataKey",
		Value:    tempLogDataKey,
		HttpOnly: true,
		//SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &cookie)

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
	db := database.InitDB()
	rdb := database.InitRedis()
	// get the regDataKey from the cookie

	cookie, err := r.Cookie("logDataKey")
	if err != nil {
		fmt.Println("Error getting the cookie:", err)
		JSONResponse(w, "Error getting the cookie key "+err.Error(), http.StatusBadRequest)
		return
	}

	// initialise the context and get the data from the redis cache
	ctx, cancelContext := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelContext()
	tempLogDataKey := cookie.Value
	tempLogDataSerialized, err := rdb.Get(ctx, tempLogDataKey).Result()
	if err != nil {
		fmt.Println("Error getting the data from redis:", err)
		JSONResponse(w, "An error occured, please check the cookie key "+err.Error(), http.StatusBadRequest)
		return
	}

	// unmarshal the data
	var tempRegData []string
	err = json.Unmarshal([]byte(tempLogDataSerialized), &tempRegData)
	if err != nil {
		fmt.Println("Error unmarshalling the data:", err)
		JSONResponse(w, "An error occured when deserializing the datas"+err.Error(), http.StatusBadRequest)
		return
	}

	loginEmail := tempRegData[0]
	loginChallenge := tempRegData[1]
	fmt.Println("Email:", loginEmail)
	fmt.Println("Challenge:", loginChallenge)

	var userFromUsers database.User
	if db.Where("email = ?", loginEmail).First(&userFromUsers).Error != nil {
		fmt.Print("User not found")
		return
	}

	var db_passkeys []database.UserPasskey
	if db.Where("user_id = ?", loginEmail).Find(&db_passkeys).Error != nil {
		fmt.Print("User not found")
		return
	}

	regUser := DefaultUser{
		ID:          []byte(loginEmail),
		Name:        userFromUsers.Username,
		DisplayName: userFromUsers.Username,
		Credentials: retrieveUserCredsAsCredentialList(loginEmail),
	}

	// create a session data object and fill it with the challenge from the begin login
	loginSessionData := webauthn.SessionData{
		Challenge: loginChallenge,
		UserID:    []byte(loginEmail),
	}

	credential, err := webAuthn.FinishLogin(regUser, loginSessionData, r)
	//fmt.Println("c in FinishLogin :")
	//credConsoleLogger(credential)
	if err != nil {
		fmt.Println(err)
		JSONResponse(w, "Error LOGIN WebAuthn"+err.Error(), http.StatusInternalServerError)
		return
	}

	// increase the sign count and update the last authenticated time
	// Find the credential
	var credentialFromDB database.UserPasskey
	if err := db.Where("credential_id = ?", base64.URLEncoding.EncodeToString(credential.ID)).First(&credentialFromDB).Error; err != nil {
		fmt.Println("Error finding the credential:", err)
		JSONResponse(w, "Error finding the credential", http.StatusInternalServerError)
		return
	}
	updateFields := database.UserPasskey{
		SignCount:           credentialFromDB.SignCount + 1,
		LastAuthenticatedAt: time.Now(),
	}
	if err := db.Model(&database.UserPasskey{}).Where("id = ?", credentialFromDB.CredentialID).Updates(updateFields).Error; err != nil {
		fmt.Println("Error updating the sign count:", err)
		JSONResponse(w, "Error updating the sign count, an internal issue occured", http.StatusInternalServerError)
		return
	}

	print("Login Success : ", base64.URLEncoding.EncodeToString(credential.PublicKey), credential.Authenticator.SignCount, "\n")

	//create a json entry that contains the username and email
	userResponse := struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Status   string `json:"status"`
	}{Email: userFromUsers.Email,
		Username: userFromUsers.Username,
		Status:   "Login success",
	}

	//w.Header().Set("Content-Type", "application/json")
	//json.NewEncoder(w).Encode(userResponse)
	//http.Redirect(w, r, "/home?email="+userFromUsers.Email+"&username="+userFromUsers.Username, http.StatusSeeOther)
	JSONResponse(w, userResponse, http.StatusOK)

}
