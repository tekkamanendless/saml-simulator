package samlsimulator

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/sirupsen/logrus"
)

type Simulator struct {
	handler *http.ServeMux
}

func (s *Simulator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func New() (*Simulator, error) {
	s := &Simulator{
		handler: http.NewServeMux(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		contents := `
<html>
	<head>
		<title>SAML Simulator Login</title>
		<meta name="viewport" content="width=device-width, height=device-height, initial-scale=1.0, minimum-scale=0.5, maximum-scale=3.0, user-scalable=yes">
		<style>
html, body {
	margin: 0;
	padding: 0;
	width: 100%;
	height: 100%;

	font-family: Roboto, sans-serif;
}

body {
	padding: 1em;
}
		</style>
	</head>
	<body>
		<h1>SAML Simulator</h1>
		<h2>Identity Provider</h2>
		<ul>
			<li>
				<a href="/">/</a> - This page.
			</li>
			<li>
				<a href="/cert">/cert</a> - The RSA certificate that will be used to sign the SAML response.
			</li>
			<li>
				<a href="/login">/login</a> - The SAML login page.
				This accepts <tt>SAMLRequest</tt> and <tt>RelayState</tt> via HTTP GET (redirect) or POST.
			</li>
			<li>
				<a href="/logout">/logout</a> - This SAML logout page.
			</li>
			<li>
				<a href="/metadata">/metadata</a> - The SAML metadata.
			</li>
		</ul>
	</body>
</html>
		`
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(contents))
	})
	mux.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		ssoURL, err := url.Parse("https://" + r.Host + "/login")
		if err != nil {
			logrus.Errorf("Could not parse SSO URL: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
			return
		}

		seed := int64(42)
		samlIDP, err := createIDP(r, seed, *ssoURL)
		if err != nil {
			logrus.Errorf("Could not create IDP: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
			return
		}

		w.Header().Add("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		{
			buffer := new(bytes.Buffer)
			pem.Encode(buffer, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: samlIDP.Certificate.Raw,
			})
			w.Write(buffer.Bytes())
		}
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
		}

		validPassword := r.Form.Get("validPassword")

		logrus.Infof("HTTP request")
		logrus.Infof("* Method: %s", r.Method)
		logrus.Infof("* Host: %s", r.Host)
		logrus.Infof("* RequestURI: %s", r.RequestURI)
		logrus.Infof("* URL: %s", r.URL)

		var message string

		ssoURL, err := url.Parse("https://" + r.Host + "/login")
		if err != nil {
			logrus.Errorf("Could not parse SSO URL: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
			return
		}

		seed := int64(42)
		samlIDP, err := createIDP(r, seed, *ssoURL)
		if err != nil {
			logrus.Errorf("Could not create IDP: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
			return
		}

		var actionURL string
		var samlRequest string
		var relayState string
		samlIDPAuthenticationRequest, err := saml.NewIdpAuthnRequest(samlIDP, r)
		if err != nil {
			logrus.Warnf("Could not parse IDP request: %v", err)
			message = err.Error()
			/*
				logrus.Errorf("Could not parse IDP request: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
				return
			*/
		} else {
			// Set up the SSO URL in advance.
			{
				var ar saml.AuthnRequest
				err := xml.Unmarshal(samlIDPAuthenticationRequest.RequestBuffer, &ar)
				if err != nil {
					logrus.Warnf("Could not parse XML: %v", err)
				} else {
					u, err := url.Parse(ar.Destination)
					if err != nil {
						logrus.Warnf("Could not parse Destination URL: %v", err)
					} else {
						samlIDP.SSOURL = *u
					}
				}
			}

			if sp, ok := samlIDP.ServiceProviderProvider.(*ServiceProviderProvider); ok {
				sp.SetRequest(samlIDPAuthenticationRequest)
			} else {
				logrus.Warnf("ServiceProviderProvider is the wrong type: %T", samlIDP.ServiceProviderProvider)
			}

			logrus.Infof("SAML IDP request buffer: %s", samlIDPAuthenticationRequest.RequestBuffer)
			if samlIDPAuthenticationRequest.IDP == nil {
				logrus.Infof("* IDP: n/a")
			} else {
				logrus.Infof("* IDP:")
				logrus.Infof("   * LogoutURL: %s", &samlIDPAuthenticationRequest.IDP.LogoutURL)
				logrus.Infof("   * MetadataURL: %s", &samlIDPAuthenticationRequest.IDP.MetadataURL)
				logrus.Infof("   * SSOURL: %s", &samlIDPAuthenticationRequest.IDP.SSOURL)
				logrus.Infof("   * ServiceProviderProvider: %v", samlIDPAuthenticationRequest.IDP.ServiceProviderProvider)
			}
			if true {
				err = samlIDPAuthenticationRequest.Validate()
				if err != nil {
					logrus.Warnf("Could not validate IDP request: %v", err)
					message = err.Error()
				}
			}
			logrus.Infof("SAML IDP Request:")
			if samlIDPAuthenticationRequest.ACSEndpoint == nil {
				logrus.Infof("* ACSEndpoint: n/a")
			} else {
				logrus.Infof("* ACSEndpoint:")
				logrus.Infof("   * Binding: %s", samlIDPAuthenticationRequest.ACSEndpoint.Binding)
				logrus.Infof("   * Index: %d", samlIDPAuthenticationRequest.ACSEndpoint.Index)
				logrus.Infof("   * IsDefault: %v", samlIDPAuthenticationRequest.ACSEndpoint.IsDefault)
				logrus.Infof("   * Location: %s", samlIDPAuthenticationRequest.ACSEndpoint.Location)
				logrus.Infof("   * ResponseLocation: %v", samlIDPAuthenticationRequest.ACSEndpoint.ResponseLocation)
			}
			{
				logrus.Infof("* Request:")
				logrus.Infof("   * AssertionConsumerServiceIndex: %s", samlIDPAuthenticationRequest.Request.AssertionConsumerServiceIndex)
				logrus.Infof("   * AssertionConsumerServiceURL: %s", samlIDPAuthenticationRequest.Request.AssertionConsumerServiceURL)
				logrus.Infof("   * AttributeConsumingServiceIndex: %s", samlIDPAuthenticationRequest.Request.AttributeConsumingServiceIndex)
				logrus.Infof("   * Consent: %s", samlIDPAuthenticationRequest.Request.Consent)
				logrus.Infof("   * Destination: %s", samlIDPAuthenticationRequest.Request.Destination)
				logrus.Infof("   * ID: %s", samlIDPAuthenticationRequest.Request.ID)
				logrus.Infof("   * IssueInstant: %v", samlIDPAuthenticationRequest.Request.IssueInstant)
				logrus.Infof("   * ProtocolBinding: %s", samlIDPAuthenticationRequest.Request.ProtocolBinding)
				logrus.Infof("   * ProviderName: %s", samlIDPAuthenticationRequest.Request.ProviderName)
				logrus.Infof("   * Version: %s", samlIDPAuthenticationRequest.Request.Version)
				logrus.Infof("   * ForceAuthn: %+v", samlIDPAuthenticationRequest.Request.ForceAuthn)
				logrus.Infof("   * IsPassive: %+v", samlIDPAuthenticationRequest.Request.IsPassive)
				if samlIDPAuthenticationRequest.Request.Issuer == nil {
					logrus.Infof("   * Issuer: n/a")
				} else {
					logrus.Infof("   * Issuer:")
					logrus.Infof("      * Value: %s", samlIDPAuthenticationRequest.Request.Issuer.Value)
				}
			}
			if samlIDPAuthenticationRequest.SPSSODescriptor == nil {
				logrus.Infof("* SPSSODescriptor: n/a")
			} else {
				logrus.Infof("* SPSSODescriptor:")
				logrus.Infof("   * CacheDuration: %v", samlIDPAuthenticationRequest.SPSSODescriptor.CacheDuration)
				logrus.Infof("   * ErrorURL: %s", samlIDPAuthenticationRequest.SPSSODescriptor.ErrorURL)
				logrus.Infof("   * ID: %s", samlIDPAuthenticationRequest.SPSSODescriptor.ID)
				logrus.Infof("   * ProtocolSupportEnumeration: %s", samlIDPAuthenticationRequest.SPSSODescriptor.ProtocolSupportEnumeration)
			}
			if samlIDPAuthenticationRequest.ServiceProviderMetadata == nil {
				logrus.Infof("* ServiceProviderMetadata: n/a")
			} else {
				logrus.Infof("* ServiceProviderMetadata:")
				logrus.Infof("   * CacheDuration: %v", samlIDPAuthenticationRequest.ServiceProviderMetadata.CacheDuration)
				logrus.Infof("   * EntityID: %s", samlIDPAuthenticationRequest.ServiceProviderMetadata.EntityID)
				logrus.Infof("   * ID: %s", samlIDPAuthenticationRequest.ServiceProviderMetadata.ID)
				logrus.Infof("   * ValidUntil: %v", samlIDPAuthenticationRequest.ServiceProviderMetadata.ValidUntil)
			}
			logrus.Infof("* Now: %v", samlIDPAuthenticationRequest.Now)
			logrus.Infof("* RelayState: %v", samlIDPAuthenticationRequest.RelayState)
			if samlIDPAuthenticationRequest.ACSEndpoint != nil && samlIDPAuthenticationRequest.ACSEndpoint.Location != "" {
				actionURL = samlIDPAuthenticationRequest.ACSEndpoint.Location
			} else {
				message = "Could not determine the action URL"
			}
			samlRequest = base64.StdEncoding.EncodeToString(samlIDPAuthenticationRequest.RequestBuffer)
			relayState = samlIDPAuthenticationRequest.RelayState
		}

		logrus.Infof("Action URL: %s", actionURL)
		logrus.Infof("SAML Request: %s", samlRequest)
		logrus.Infof("Relay State: %s", relayState)

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		logrus.Infof("Username: %s", username)
		logrus.Infof("Password: %s", strings.Repeat("*", len(password)))

		// If we don't have an error message already, then attempt to validate the username/password.
		if message == "" {
			if username != "" && password != "" && (validPassword == "" || password == validPassword) {
				logrus.Infof("Login: rendering the auto form.")

				randomSource := rand.NewSource(time.Now().Unix())
				randomReader := rand.New(randomSource)
				sessionID := make([]byte, 32)
				randomReader.Read(sessionID)
				sessionIndex := make([]byte, 32)
				randomReader.Read(sessionIndex)
				maxAge := 1 * time.Hour
				newSession := &saml.Session{
					ID:         base64.StdEncoding.EncodeToString(sessionID),
					NameID:     username,
					CreateTime: saml.TimeNow(),
					ExpireTime: saml.TimeNow().Add(maxAge),
					Index:      hex.EncodeToString(sessionIndex),
					UserName:   username,
					//Groups:                user.Groups[:],
					//UserEmail:             user.Email,
					//UserCommonName:        user.CommonName,
					//UserSurname:           user.Surname,
					//UserGivenName:         user.GivenName,
					//UserScopedAffiliation: user.ScopedAffiliation,
				}

				assertionMaker := samlIDPAuthenticationRequest.IDP.AssertionMaker
				if assertionMaker == nil {
					assertionMaker = saml.DefaultAssertionMaker{}
				}
				err = assertionMaker.MakeAssertion(samlIDPAuthenticationRequest, newSession)
				if err != nil {
					logrus.Errorf("Failed to make assertion: %s", err)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
					return
				}

				useBuiltinForm := false
				if useBuiltinForm {
					// The builtin form works, but there's nothing visible on the page.

					err = samlIDPAuthenticationRequest.WriteResponse(w)
					if err != nil {
						logrus.Errorf("Failed to write response: %s", err)
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
						return
					}
					return
				}

				// Our version of the form will also show some text to make it clear to the user that
				// we're waiting on the service provider.

				var samlResponse string
				// The code to get the SAML response has been copied from the `saml` package.
				// See: https://github.com/crewjam/saml/blob/60a32b32095ab361c827116afd3f0041874c6c9c/identity_provider.go#L880
				{
					if samlIDPAuthenticationRequest.ResponseEl == nil {
						if err := samlIDPAuthenticationRequest.MakeResponse(); err != nil {
							logrus.Errorf("Failed to create response: %s", err)
							w.WriteHeader(http.StatusInternalServerError)
							w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
							return
						}
					}

					doc := etree.NewDocument()
					doc.SetRoot(samlIDPAuthenticationRequest.ResponseEl)
					responseBuf, err := doc.WriteToBytes()
					if err != nil {
						logrus.Errorf("Failed to write response buffer: %s", err)
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
						return
					}
					samlResponse = base64.StdEncoding.EncodeToString(responseBuf)
				}

				switch samlIDPAuthenticationRequest.ACSEndpoint.Binding {
				case saml.HTTPPostBinding:
					contents := `
<html>
	<head>
		<title>SAML Simulator Login</title>
		<meta name="viewport" content="width=device-width, height=device-height, initial-scale=1.0, minimum-scale=0.5, maximum-scale=3.0, user-scalable=yes">
		<style>
html, body {
	margin: 0;
	padding: 0;
	width: 100%;
	height: 100%;

	font-family: Roboto, sans-serif;
}

body {
	padding: 1em;
}
		</style>
		<script>
window.addEventListener('load', e => {
	console.log("Page loaded.");

	document.querySelector('#form').submit();
});
		</script>
	</head>
	<body>
		<h1>SAML Simulator</h1>
		<h2>Identity Provider</h2>
		<p>
			Your resonse has been submitted to ` + html.EscapeString(actionURL) + `; please wait...
		</p>
		<form id="form" method="POST" action="` + html.EscapeString(actionURL) + `">
			<input name="SAMLResponse" type="hidden" value="` + html.EscapeString(samlResponse) + `">
			<input name="RelayState" type="hidden" value="` + html.EscapeString(relayState) + `">
		</form>
	</body>
</html>
`
					w.Header().Add("Content-Type", "text/html")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(contents))
					return
				default:
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(fmt.Sprintf("Unsupported binding: %s", samlIDPAuthenticationRequest.ACSEndpoint.Binding)))
					return
				}
			}
		}

		logrus.Infof("Login: showing the login screen.")

		if username != "" {
			if password == "" || (validPassword != "" && password != validPassword) {
				message = "Invalid username or password."
			}
		}

		logrus.Infof("Login: message: %s", message)

		contents := `
<html>
	<head>
		<title>SAML Simulator Login</title>
		<meta name="viewport" content="width=device-width, height=device-height, initial-scale=1.0, minimum-scale=0.5, maximum-scale=3.0, user-scalable=yes">
		<style>
html, body {
	margin: 0;
	padding: 0;
	width: 100%;
	height: 100%;

	font-family: Roboto, sans-serif;
}

body {
	display: flex;
	flex-direction: column;

	align-items: center;
	align-content: center;

	background-color: black;
}

input, button {
	box-sizing: border-box;
	display: block;
	border-radius: 0.6em;
	padding: 0.5em;
	width: 220px;
	font-size: 1.1em;
	margin: auto;
}

button {
	border-radius: 0.6em;
}

.banner {
	box-sizing: border-box;

	margin: 1em;

	padding: 1em;

	border: 1px solid gray;
	border-radius: 1em;
	background-color: lightgray;
}

.content {
	flex: 1;

	box-sizing: border-box;

	display: flex;
}

.form {
	margin: auto;

	padding: 1em;

	border: 1px solid gray;
	border-radius: 1em;
	background-color: white;
}

.field {
	padding: 0.5em;
}
.field .value {
	margin: auto;
}

.actions {
	padding: 1em;
}

.actions button {
	display: block;
	margin: auto;
	padding: 0.5em;
}

#login-message {
	display: none;
}

.footer {
	box-sizing: border-box;

	width: 100%;

	padding: 0.5em;

	background-color: gray;
	overflow-x: auto;
}
		</style>
		<script>
window.addEventListener('load', e => {
	console.log("Page loaded.");
	for (let element of document.querySelectorAll('input')) {
		element.addEventListener('keypress', e => {
			if (event.key === 'Enter') {
				document.querySelector('#submit').click();
			}
		});
	}
	document.querySelector('#submit').addEventListener('click', e => {
		console.log("Submitted.");
		let username = document.querySelector('#username').value;
		let password = document.querySelector('#password').value;
		if (username === '') {
			showError('Please provide a username.');
			return;
		}
		if (password === '') {
			showError('Please provide a password.');
			return;
		}

		document.querySelector('#submit').disabled = true;

		document.querySelector('#form').submit();
	});
`
		if message != "" {
			contents += `
	showError('` + strings.ReplaceAll(message, `'`, `\'`) + `');
			`
		}
		contents += `
});

function showError(message) {
	let messageBox = document.querySelector('#login-message');
	if (!message) {
		messageBox.style.display = 'none';
		return;
	}
	messageBox.style.display = 'block';
	messageBox.innerHTML = message;
}
		</script>
	</head>
	<body>
		<div class="banner">
			This is a SAML simulator, simulating an "identity provider".
			You may log in with any username.
`
		if validPassword == "" {
			contents += `The password doesn't matter, as long as it's not empty.`
		} else {
			contents += `The password <tt>` + html.EscapeString(validPassword) + `</tt> will allow you to log in; all other passwords will fail.`
		}
		contents += `
		</div>
		<div class="content">
			<div class="form">
				<form id="form" method="POST">
					<input id="SAMLRequest" name="SAMLRequest" type="hidden" value="` + html.EscapeString(samlRequest) + `">
					<input id="RelayState" name="RelayState" type="hidden" value="` + html.EscapeString(relayState) + `">

					<h2>Login</h2>
					<div id="login-message" class="banner"></div>
					<div class="field">
						<div class="value"><input id="username" name="username" type="text" placeholder="Username" autofocus></div>
					</div>
					<div class="field">
						<div class="value"><input id="password" name="password" placeholder="Password" type="password"></div>
					</div>
				</form>
				<div class="field">
					<div class="value"><button id="submit">Log in</button></div>
				</div>
			</div>
		</div>
		<div class="footer">
			On login, this will POST to: `
		if actionURL == "" {
			contents += `n/a`
		} else {
			contents += html.EscapeString(actionURL)
		}
		contents += `<br>
			Relay state: `
		if relayState == "" {
			contents += `n/a`
		} else {
			contents += html.EscapeString(relayState)
		}
		contents += `<br>
		</div>
	</body>
</html>
		`
		w.Header().Add("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(contents))
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
		}

		contents := `
<html>
	<head>
		<title>SAML Simulator Login</title>
		<meta name="viewport" content="width=device-width, height=device-height, initial-scale=1.0, minimum-scale=0.5, maximum-scale=3.0, user-scalable=yes">
		<style>
html, body {
	margin: 0;
	padding: 0;
	width: 100%;
	height: 100%;

	font-family: Roboto, sans-serif;
}

body {
	padding: 1em;
}
		</style>
	</head>
	<body>
		<h1>SAML Simulator</h1>
		<h2>Identity Provider</h2>
		<p>
			You have been logged out.
		</p>
	</body>
</html>
		`
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(contents))
	})
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		ssoURL, err := url.Parse("https://" + r.Host + "/login")
		if err != nil {
			logrus.Errorf("Could not parse SSO URL: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
			return
		}

		seed := int64(42)
		samlIDP, err := createIDP(r, seed, *ssoURL)
		if err != nil {
			logrus.Errorf("Could not create IDP: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
			return
		}

		samlIDP.ServeMetadata(w, r)
	})

	s.handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		logrus.WithContext(ctx).Infof("Request: %s %s", r.Method, r.URL)
		logrus.WithContext(ctx).Infof("Path: %s", r.URL.Path)

		{
			logrus.WithContext(ctx).Debugf("URL: %v", r.URL)
			logrus.WithContext(ctx).Debugf("Host: %s", r.Host)
			headers := []string{}
			for key := range r.Header {
				headers = append(headers, key)
			}
			sort.Strings(headers)
			logrus.WithContext(ctx).Debugf("Headers: (%d)", len(headers))
			for _, key := range headers {
				for _, value := range r.Header.Values(key) {
					logrus.WithContext(ctx).Debugf("* %s: %v", key, value)
				}
			}
		}

		mux.ServeHTTP(w, r)
	})
	return s, nil
}
