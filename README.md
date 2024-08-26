# Passkeys Proof of Concept (PoC)

This repository contains a proof-of-concept (PoC) for implementing passkeys according to WebAuthn specifications. It is designed to demonstrate passwordless authentication for both web browsers and mobile devices.

## Repository Structure

The repository consists of two branches:

### `main` Branch

- **Web Browser Implementation**: Includes an RP (Relying Party) server written in Go, utilizing the `github.com/go-webauthn/webauthn/webauthn` package.
- **Client-Side Implementation**: Features a client-side implementation for testing passkey operations such as login, creation, deletion, and retrieval.
- **AAGUID Parser**: Contains an AAGUID parser using common blob files.

### `mobile` Branch

- **Mobile Passkeys**: Focuses on mobile passkeys and contains only the RP server part.
- This branch implement the necessary APIs to work as an RP server which works with the Flutter package provided by Corbado Auth ([Corbado Passkeys](https://pub.dev/packages/passkeys)) and all other packages that follows the WebAuthn Specs.
- ([WebAuthn Specs](https://www.w3.org/TR/webauthn-2/))
- The Corbado Package have no open-source rp Server yet, so this can serve as well.
  
## Project Background

The project was developed during an internship as a PoC (Proof of Concept) for passwordless WebAuthn authentication. 
The aim was to demonstrate the feasibility and functionality of passkeys in real-world applications. 

## Future Development

After the POC, the passkeys are now being implemented in the main infrastructures with more refined code and features. 
However, updates to this public repository will be made as time permits.

## Getting Started

### Prerequisites

- Go (for the web implementation)
- Flutter (for the mobile implementation)
- Docker (optional, for running the application in containers)
