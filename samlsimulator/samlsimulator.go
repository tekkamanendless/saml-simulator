package samlsimulator

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"

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
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
		}

		// TODO TODO TODO
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
		}

		validPassword := r.Form.Get("validPassword")

		ssoURL, err := url.Parse("/login")
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

		actionURL := "https://bad-saml-target.example.com/sorry"
		var samlRequest string
		var relayState string
		samlIDPAuthenticationRequest, err := saml.NewIdpAuthnRequest(samlIDP, r)
		if err != nil {
			logrus.Warnf("Could not parse IDP request: %v", err)
			/*
				logrus.Errorf("Could not parse IDP request: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
				return
			*/
		} else {
			//actionURL = samlIDPAuthenticationRequest.IDP.SSOURL.String()
			if samlIDPAuthenticationRequest.ACSEndpoint != nil && samlIDPAuthenticationRequest.ACSEndpoint.Location != "" {
				actionURL = samlIDPAuthenticationRequest.ACSEndpoint.Location
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

		if username != "" && password != "" && (validPassword == "" || password == validPassword) {
			logrus.Infof("Login: rendering the auto form.")

			var samlResponse string // TODO

			contents := `
<html>
	<head>
		<title>SAML Simulator Submit</title>
		<script>
window.addEventListener('load', e => {
	console.log("Page loaded.");

	document.querySelector('#form').submit();
});
		</script>
	</head>
	<body>
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
		} else {
			logrus.Infof("Login: showing the login screen.")

			var message string
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
		<style>
html, body {
	margin: 0;
	padding: 0;
	width: 100%;
	height: 100%;
}

body {
	display: flex;
	flex-direction: column;

	align-items: center;
	align-content: center;

	background-color: black;
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
	display: flex;
	flex-direction: row;
	padding: 0.5em;
}
.field .key {
	width: 100px;
}
.field .value {
	flex: 1;
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
	showMessage('` + strings.ReplaceAll(message, `'`, `\'`) + `');
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
						<div class="key">Username:</div>
						<div class="value"><input id="username" name="username" type="text" autofocus></div>
					</div>
					<div class="field">
						<div class="key">Password:</div>
						<div class="value"><input id="password" name="password" type="text"></div>
					</div>
				</form>
				<div class="actions">
					<button id="submit">Log in</button>
				</div>
			</div>
		</div>
		<div class="footer">
			On login, this will POST to: ` + html.EscapeString(actionURL) + `<br>
			Relay state: ` + html.EscapeString(relayState) + `
		</div>
	</body>
</html>
		`
			w.Header().Add("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(contents))
		}
	})
	mux.HandleFunc("/sso2", func(w http.ResponseWriter, r *http.Request) {
		ssoURL, err := url.Parse("/sso2")
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

		samlIDP.ServeSSO(w, r)
	})
	mux.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		ssoURL, err := url.Parse("/sso")
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

			/*
				certPrivKeyPEM := new(bytes.Buffer)
				pem.Encode(certPrivKeyPEM, &pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(*(samlIDP.Key.(**rsa.PrivateKey))),
				})
				w.Write(certPrivKeyPEM.Bytes())
			*/
		}
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
