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
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// BeginMobileRegistration is the handler that will be called when the user wants to register a new credential
// It will generate the options that will be sent to the client following the WebAuthn protocol
func BeginMobileRegistration(w http.ResponseWriter, r *http.Request) {
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		//fmt.Println(err)
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	db := database.InitDB()
	rdb := database.InitRedis()

	ctx, cancelContext := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelContext()

	//fmt.Println("REDIS CLIENT:", rdb)
	//fmt.Println("REDIS CLIENT:", rdb.Ping(ctx).Val())
	//fmt.Println("Context:", ctx)

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

	var passkeyUser = DefaultUser{

		ID:          []byte(userFromDb.Email),
		Name:        userFromDb.Username,
		DisplayName: userFromDb.Username,
		//Icon:        "https://example.com/icon.png",
		//Credentials: retrieveUserCredentials(email), // No more need to do it here, it's done in the BeginRegistration function
	}

	options, session, err := webAuthn.BeginRegistration(passkeyUser, webauthn.WithExclusions(retrieveUserCredsAsDescriptor(emailBody.Email)))

	if err != nil {
		fmt.Println(err)

		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	// Those two variables are used to store the challenge and the email of the user
	// between the Begin and Finish registration, in prod, they can be in a redis cache
	RegistrationChallenge = string(session.Challenge)
	RegistrationUserEmail = emailBody.Email

	//create a list of string contains the email and challenge
	//to store in the redis cache

	var tempRegData = []string{emailBody.Email, string(session.Challenge)}
	tempRegDataSerialized, err := json.Marshal(tempRegData)
	if err != nil {
		log.Fatalf("could not marshal data: %v", err)
		JSONResponse(w, "An error occured", http.StatusInternalServerError)
		return
	}
	tempRegDataKey := GenerateUUID()
	_, err = rdb.Set(ctx, tempRegDataKey, tempRegDataSerialized, database.RedisExpirationDuration).Result()
	if err != nil {
		fmt.Println("Error storing registration data in redis:", err)
		JSONResponse(w, "An error occured", http.StatusInternalServerError)
		return
	}

	// add the key to the http cookie
	cookie := http.Cookie{
		Name:     "regDataKey",
		Value:    tempRegDataKey,
		HttpOnly: true,
		//SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &cookie)

	//var sentOptions = mobileCredentialOptionBuilder(options.Response)
	JSONResponse(w, options, http.StatusOK) // return the options generated
}

func FinishMobileRegistration(w http.ResponseWriter, r *http.Request) {

	db := database.InitDB()
	rdb := database.InitRedis()
	// get the regDataKey from the cookie

	cookie, err := r.Cookie("regDataKey")
	if err != nil {
		fmt.Println("Error getting the cookie:", err)
		JSONResponse(w, "Error getting the cookie key "+err.Error(), http.StatusBadRequest)
		return
	}

	// initialise the context and get the data from the redis cache
	ctx, cancelContext := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelContext()
	tempRegDataKey := cookie.Value
	tempRegDataSerialized, err := rdb.Get(ctx, tempRegDataKey).Result()
	if err != nil {
		fmt.Println("Error getting the data from redis:", err)
		JSONResponse(w, "An error occured, please check the cookie key "+err.Error(), http.StatusBadRequest)
		return
	}

	// unmarshal the data
	var tempRegData []string
	err = json.Unmarshal([]byte(tempRegDataSerialized), &tempRegData)
	if err != nil {
		fmt.Println("Error unmarshalling the data:", err)
		JSONResponse(w, "An error occured when deserializing the datas"+err.Error(), http.StatusBadRequest)
		return
	}

	registrationEmail := tempRegData[0]
	registrationChallenge := tempRegData[1]
	fmt.Println("Email:", registrationEmail)
	fmt.Println("Challenge:", registrationChallenge)
	RegistrationChallenge = registrationChallenge
	RegistrationUserEmail = registrationEmail

	if RegistrationUserEmail == "" {
		fmt.Println("Error : Follow the required steps : The user email is empty, so no beginning of registration")
		JSONResponse(w, "Error : Follow the required steps", http.StatusBadRequest)
	}

	fmt.Println("Last email:", RegistrationUserEmail)
	var userFromUsers database.User
	if db.Where("email = ?", RegistrationUserEmail).First(&userFromUsers).Error != nil {
		fmt.Print("User not found")
		JSONResponse(w, "User not found", http.StatusBadRequest)
		return
	}

	regSessionData := webauthn.SessionData{
		Challenge:            RegistrationChallenge,
		UserID:               []byte(RegistrationUserEmail), //
		AllowedCredentialIDs: [][]byte{},                    // Vide pour cet exemple
		Expires:              time.Date(0001, time.January, 1, 0, 0, 0, 0, time.UTC),
		UserVerification:     protocol.VerificationPreferred,
	}

	regUser := DefaultUser{
		ID:          []byte(userFromUsers.Email),
		Name:        userFromUsers.Username,
		DisplayName: userFromUsers.Username,
	}

	c, err := webAuthn.FinishRegistration(regUser, regSessionData, r)
	if err != nil {
		fmt.Println(err)
		JSONResponse(w, "Error creating WebAuthn : "+err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("credential content:", c)
	//Print the informations aboout the credential
	credConsoleLogger(c)

	//print the user ID base64url
	fmt.Println("User ID:", base64.URLEncoding.EncodeToString(regUser.ID))

	newPassKeyEntry := database.UserPasskey{
		UserID:          RegistrationUserEmail,
		PublicKey:       base64.URLEncoding.EncodeToString(c.PublicKey),
		CredentialID:    base64.URLEncoding.EncodeToString(c.ID),
		AttestationType: c.AttestationType,
		Transport:       joinTransports(c.Transport),
		UserPresent:     c.Flags.UserPresent,
		UserVerified:    c.Flags.UserVerified,
		BackupEligible:  c.Flags.BackupEligible,
		BackupState:     c.Flags.BackupState,
		AAGUID:          base64.URLEncoding.EncodeToString(c.Authenticator.AAGUID),
		SignCount:       c.Authenticator.SignCount,
		Attachment:      string(c.Authenticator.Attachment),
	}
	//then we save the credential in the database,
	// the obligatories are just pb_key, user_id, credential_id,
	// the rest is optional
	/*newPassKeyEntry := database.UserPasskey{
		UserID:         data.UserID,
		CredentialID:   data.CredentialID,
		Attachment:     data.AuthData,
		ClientDataHash: data.ClientDataHash,
	}
	*/
	errv := db.Create(&newPassKeyEntry)
	if errv.Error != nil {
		fmt.Println("Error creating passkey entry: ", errv.Error)
		JSONResponse(w, "Error creating passkey entry "+errv.Error.Error(), http.StatusInternalServerError)
		return
	}
	//credConsoleLogger(c)
	fmt.Println("Registration Success")

	JSONResponse(w, c, http.StatusCreated)

}
