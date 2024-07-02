package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"webauthn-example/database"

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

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		//fmt.Println(err)
		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

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
		//Credentials: retrieveUserCredentials(email), // Initialisez avec des données par défaut si nécessaire
	}

	/* for selecting the authenticator
	authSelect := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
		RequireResidentKey: protocol.ResidentKeyNotRequired(),
		UserVerification: protocol.VerificationRequired,
	}
	*/

	options, session, err := webAuthn.BeginRegistration(passkeyUser, webauthn.WithExclusions(retrieveUserCredsAsDescriptor(email)))
	if err != nil {
		fmt.Println(err)

		JSONResponse(w, "Error creating WebAuthn"+err.Error(), http.StatusInternalServerError)
	}

	RegistrationChallenge = string(session.Challenge)

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

	//then we save the credential in the database,
	// the obligatories are just pb_key, user_id, credential_id,
	// the rest is optional
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

	errv := db.Create(&newPassKeyEntry)
	if errv.Error != nil {
		fmt.Println("Error creating passkey entry:", errv.Error)
		return
	}
	//make new credential
	fmt.Println("c in FinishRegistration\n----------------")
	credConsoleLogger(c)
	fmt.Println("Registration Success")

	JSONResponse(w, "Registration Success"+c.Descriptor().AttestationType, http.StatusOK)

}

// function that take the aaguid and retun the formatted UUID
func formatAAGUID(aaguid []byte) string {
	uuidHex := hex.EncodeToString(aaguid)
	return fmt.Sprintf("%s-%s-%s-%s-%s", uuidHex[0:8], uuidHex[8:12], uuidHex[12:16], uuidHex[16:20], uuidHex[20:])

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

	// search the email in users_table first
	var userFromUsers database.User
	if db.Where("email = ?", email).First(&userFromUsers).Error != nil {
		fmt.Print("User not exist")
		return
	}

	// then in passkeys_table
	var db_passkeys []database.UserPasskey
	if db.Where("user_id = ?", email).Find(&db_passkeys).Error != nil {
		fmt.Print("User has no passkey")
		return
	}

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
	fmt.Println("c in FinishLogin :")
	credConsoleLogger(credential)
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

// convert a []protocol.AuthenticatorTransport to a string for storage
func joinTransports(transports []protocol.AuthenticatorTransport) string {
	transportStrings := make([]string, len(transports))
	for i, transport := range transports {
		transportStrings[i] = string(transport)
	}
	return strings.Join(transportStrings, ",")
}

// convert a string to a []protocol.AuthenticatorTransport
func splitTransports(transportStr string) []protocol.AuthenticatorTransport {
	transportStrings := strings.Split(transportStr, ",")
	transports := make([]protocol.AuthenticatorTransport, len(transportStrings))
	for i, transport := range transportStrings {
		transports[i] = protocol.AuthenticatorTransport(transport)
	}
	return transports
}

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

func GetUserCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	db := database.InitDB()
	//fmt.Println("email:", email)

	// retrieve the user from the database
	var userFromUsers database.User
	if db.Where("email = ?", email).First(&userFromUsers).Error != nil {
		fmt.Print("User not found")
		return
	}
	// retrieve the user passkeys from the database
	var userPasskeys []database.UserPasskey
	if db.Where("user_id = ?", email).Find(&userPasskeys).Error != nil {
		fmt.Print("User not found")
		return
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

	var aaguidSchema database.AAGUIDSchema
	aaguidSchema.Items = database.AAGUIDJsonLoader()
	if aaguidSchema.Items == nil {
		fmt.Println("Error loading AAGUID schema")
		return
	}

	var passkeyEntries []PasskeyEntry
	var passkeyEntry PasskeyEntry
	for _, passkey := range userPasskeys {
		aaguidItem := database.RetrieveAAGUIDInfo(formatAAGUID(passkey.AAGUID), aaguidSchema)
		//test if empty
		if (aaguidItem == database.AAGUIDItem{}) {
			passkeyEntry.Description = "Unknown"
			passkeyEntry.ImageDark = "Unknown"
			passkeyEntry.ImageLight = "Unknown"
			fmt.Println("AAGUID not found in schema")
		} else {
			passkeyEntry.Description = aaguidItem.Name
			passkeyEntry.ImageDark = aaguidItem.IconDark
			passkeyEntry.ImageLight = aaguidItem.IconLight
		}
		passkeyEntry.CredentialID = base64.RawStdEncoding.EncodeToString(passkey.CredentialID)
		passkeyEntry.AAGUID = formatAAGUID(passkey.AAGUID)
		passkeyEntry.VerMethod = "FIDO2"
		passkeyEntry.CreatedAt = passkey.CreatedAt.Format(time.RFC3339)

		passkeyEntries = append(passkeyEntries, passkeyEntry)

	}

	JSONResponse(w, passkeyEntries, http.StatusOK)
}

func retrieveUserCredsAsDescriptor(email string) []protocol.CredentialDescriptor {
	db := database.InitDB()

	var credentialEntries []database.UserPasskey
	var userCredentials []protocol.CredentialDescriptor

	//get the user from the database
	if db.Where("user_id = ?", email).Find(&credentialEntries).Error != nil {
		fmt.Print("User not found")
		return userCredentials
	}

	for _, userFromPasskeyUser := range credentialEntries {
		userCredentials = append(userCredentials, protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    userFromPasskeyUser.CredentialID,
			Transport:       splitTransports(userFromPasskeyUser.Transport),
			AttestationType: userFromPasskeyUser.AttestationType,
		})
	}

	return userCredentials

}

func retrieveUserCredsAsCredentialList(email string) []webauthn.Credential {
	db := database.InitDB()
	//get the user from the database
	var credentialEntries []database.UserPasskey
	var userCredentials []webauthn.Credential

	if db.Where("user_id = ?", email).Find(&credentialEntries).Error != nil {
		fmt.Print("User not found")
		return userCredentials
	}

	for _, userFromPasskeyUser := range credentialEntries {
		userCredentials = append(userCredentials, webauthn.Credential{
			ID:        userFromPasskeyUser.CredentialID,
			PublicKey: userFromPasskeyUser.PublicKey,
			/*
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
			*/
		})
	}

	return userCredentials

}

func credConsoleLogger(c *webauthn.Credential) {
	fmt.Println("----------------------------------------")
	fmt.Println("Credential ID:", base64.URLEncoding.EncodeToString(c.ID))
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
	fmt.Println("----------------------------------------")
}
