# saml-simulator
A SAML simulator to aid in the development and testing of applications that authenticate using SAML.

## Endpoints

### `/cert`
This will return a plaintext copy of the cert that will be used.

### `/login`
This is the main landing for SSO/login.

This will prompt the user for her username and password, and it will submit to itself.

Upon failure, it will render the same page with an error message.

Upon success, it will render a simple page with a single form and use Javascript to auto-submit that form, which will POST back to the service provider's URL.

### `/logout`
TODO: THIS

### `/sso`
This is a test endpoint for the built-in IDP.
This will likely be kind of good, but not quite good enough for our use case.
