package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LDiaks01/WebAuthn_PoC/database"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Print the credential to the console
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

// handle the printing of the user credentials in the home webpage
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

	var aaguidSchema database.AAGUIDSchema
	aaguidSchema.Items = database.AAGUIDJsonLoader()
	if aaguidSchema.Items == nil {
		fmt.Println("Error loading AAGUID schema")
		return
	}

	var passkeyEntries []PasskeyEntry
	var passkeyEntry PasskeyEntry
	for _, passkey := range userPasskeys {
		aaguidItem := database.RetrieveAAGUIDInfo(passkey.AAGUID, aaguidSchema)
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
		//passkeyEntry.CredentialID = base64.RawStdEncoding.EncodeToString(passkey.CredentialID)
		passkeyEntry.CredentialID = passkey.CredentialID
		passkeyEntry.AAGUID = passkey.AAGUID
		passkeyEntry.VerMethod = "FIDO2"
		passkeyEntry.CreatedAt = passkey.CreatedAt.Format(time.RFC3339)

		passkeyEntries = append(passkeyEntries, passkeyEntry)

	}

	JSONResponse(w, passkeyEntries, http.StatusOK)
}

// Retrieve the user credentials from the database as a list of protocol.CredentialDescriptor
// This is used to populate the user's credentials when registering
// to avoid registering the same credential twice
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

		credID, err := base64.URLEncoding.DecodeString(userFromPasskeyUser.CredentialID)
		if err != nil {
			return userCredentials
		}

		userCredentials = append(userCredentials, protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    credID,
			Transport:       splitTransports(userFromPasskeyUser.Transport),
			AttestationType: userFromPasskeyUser.AttestationType,
		})
	}

	return userCredentials

}

func retrieveUserCredsAsMobileDescriptor(email string) []protocol.CredentialDescriptor {
	db := database.InitDB()

	var credentialEntries []database.UserPasskey
	var userCredentials []protocol.CredentialDescriptor

	//get the user from the database
	if db.Where("user_id = ?", email).Find(&credentialEntries).Error != nil {
		fmt.Print("User not found")
		return userCredentials
	}

	for _, userFromPasskeyUser := range credentialEntries {

		credID, err := base64.URLEncoding.DecodeString(userFromPasskeyUser.CredentialID)

		if err != nil {
			return userCredentials
		}

		userCredentials = append(userCredentials, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: credID,
			Transport:    splitTransports(userFromPasskeyUser.Transport),
			//[]protocol.AuthenticatorTransport{protocol.AuthenticatorTransport("internal"), protocol.AuthenticatorTransport("ble")},
			//AttestationType: userFromPasskeyUser.AttestationType,
		})
	}

	return userCredentials

}

// Retrieve the user credentials from the database as a list of webauthn.Credential
// This is used to populate the user's credentials when they log in
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
		credID, err := base64.URLEncoding.DecodeString(userFromPasskeyUser.CredentialID)
		if err != nil {
			fmt.Println("Error decoding credential ID:", err)
			return userCredentials
		}

		publicKey, err := base64.URLEncoding.DecodeString(userFromPasskeyUser.PublicKey)
		if err != nil {
			// handle the error, e.g. log or return an error response
			fmt.Println("Error decoding public key:", err)
			return userCredentials
		}

		aaguid, err := base64.URLEncoding.DecodeString(userFromPasskeyUser.AAGUID)
		if err != nil {
			// handle the error, e.g. log or return an error response
			fmt.Println("Error decoding public key:", err)
			return userCredentials
		}

		userCredentials = append(userCredentials, webauthn.Credential{
			ID: credID,

			PublicKey: publicKey,

			Authenticator: webauthn.Authenticator{
				AAGUID:     aaguid,
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

	return userCredentials

}

func CCDToString(value string) []byte {
	var encoded bytes.Buffer
	encoded.WriteByte('"')

	for _, r := range value {
		if r == '"' {
			encoded.WriteString(`\"`)
		} else if r == '\\' {
			encoded.WriteString(`\\`)
		} else if r < 0x20 || r == 0x7F {
			// Escape non-printable ASCII characters
			encoded.WriteString(fmt.Sprintf(`\u%04x`, r))
		} else if r > 0x7F && r < 0xA0 {
			// Escape non-printable non-ASCII characters
			encoded.WriteString(fmt.Sprintf(`\u%04x`, r))
		} else {
			// Directly append printable characters
			encoded.WriteRune(r)
		}
	}
	encoded.WriteByte('"')
	return encoded.Bytes()
}

func SerializeClientData(typeParam, challenge, origin string, crossOrigin bool, remainingFields map[string]interface{}) string {
	var result bytes.Buffer

	// Append initial parts
	result.WriteString(`{"type":`)
	result.Write(CCDToString(typeParam))
	result.WriteString(`,"challenge":`)
	result.Write(CCDToString(challenge))
	result.WriteString(`,"origin":`)
	result.Write(CCDToString(origin))
	result.WriteString(`,"crossOrigin":`)

	// Handle crossOrigin
	if !crossOrigin {
		result.WriteString("false")
	} else {
		result.WriteString("true")
	}
	result.WriteString("}")
	// Remove the specified fields from remainingFields
	// then, SHA256 the result
	hasher := sha256.New()
	hasher.Write(result.Bytes())
	hash := hasher.Sum(nil)
	b64format := base64.StdEncoding.EncodeToString(hash)
	//print("b64urlformat:", b64format)
	//hashStr := hex.EncodeToString(hash)
	//shortHashStr := hashStr[:32]
	// return the first 32 bytes of the hash as a hex string
	return b64format
}

// function that take the aaguid and retun the formatted UUID
// then the return can be used to search the AAGUID in the JSON schema
func formatAAGUID(aaguid []byte) string {
	uuidHex := hex.EncodeToString(aaguid)
	return fmt.Sprintf("%s-%s-%s-%s-%s", uuidHex[0:8], uuidHex[8:12], uuidHex[12:16], uuidHex[16:20], uuidHex[20:])

}

// convert a []protocol.AuthenticatorTransport to a string for storage
func joinTransports(transports []protocol.AuthenticatorTransport) string {
	transportStrings := make([]string, len(transports))
	for i, transport := range transports {
		transportStrings[i] = string(transport)
	}
	return strings.Join(transportStrings, ",")
}

// convert a string to a []protocol.AuthenticatorTransport for use in the protocol
func splitTransports(transportStr string) []protocol.AuthenticatorTransport {
	transportStrings := strings.Split(transportStr, ",")
	transports := make([]protocol.AuthenticatorTransport, len(transportStrings))
	for i, transport := range transportStrings {
		transports[i] = protocol.AuthenticatorTransport(transport)
	}
	return transports
}

func GenerateUUID() string {
	id := uuid.New()
	return id.String()
}
