# saml-simulator
This is a SAML "identity provider" simulator to aid in the development and testing of applications that authenticate using SAML.

Caveats:

1. This does not provide any metadata endpoint.
1. This does not attempt to validate any metadata from the "service provider" via its metadata endpoint, if any.
1. This will accept any URL as its SSO/login endpoint as long as `/login` is accessed.  The domain, port number, etc., do not matter.

## Usage
You may configure the application using any of the following command-line parameters or environment variables.
(Command-line arguments take precedence over environment variables.)

```
  -debug
        Enable this for more verbose output.
        Environment variable: DEBUG
  -web.address string
        The address to listen on.
        Environment variable: WEB_ADDRESS (default "0.0.0.0")
  -web.port int
        The port number to listen on.
        Environment variable: WEB_PORT (default 8080)
  -web.ssl-cert string
        The path to the SSL cert file.
        Both this and 'web.ssl-key' must be present for HTTPS.
        Environment variable: WEB_SSL_CERT
  -web.ssl-key string
        The path to the SSL key file.
        Both this and 'web.ssl-cert' must be present for HTTPS.
        Environment variable: WEB_SSL_KEY
```


## Endpoints
This web service provides the following endpoints.

### `/cert`
This will return a plaintext copy of the cert that will be used.

### `/login`
This is the main landing for SSO/login.

This will prompt the user for her username and password, and it will submit to itself.

Upon failure, it will render the same page with an error message.

Upon success, it will render a simple page with a single form and use Javascript to auto-submit that form, which will POST back to the service provider's URL.

### `/logout`
This is the SSO/logout endpoint.

It does nothing but prints that the user has been logged out.

### `/sso`
(Testing only)

This is a test endpoint for the built-in IDP from `crewjam/saml`.
This will likely be kind of good, but not quite good enough for our more flexible use cases.
Anecdotally, the this endpoint requires the service provider information to be pre-configured, and this tool provides no way to do that.
