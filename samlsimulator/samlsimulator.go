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
	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
		}

		validPassword := r.Form.Get("validPassword")

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
		samlIDPAuthenticationRequest, err := saml.NewIdpAuthnRequest(samlIDP, r)
		if err != nil {
			logrus.Errorf("Could not parse IDP request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Internal server error: %v", err)))
			return
		}

		actionURL := samlIDPAuthenticationRequest.IDP.SSOURL.String()
		samlRequest := base64.StdEncoding.EncodeToString(samlIDPAuthenticationRequest.RequestBuffer)
		relayState := samlIDPAuthenticationRequest.RelayState

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
let VALID_PASSWORD = '` + base64.StdEncoding.EncodeToString([]byte(validPassword)) + `';
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
			showError('Please provider a username.');
			return;
		}
		if (password === '') {
			showError('Please provider a password.');
			return;
		}
		let encodedPassword = btoa(password);
		if (VALID_PASSWORD !== '' && encodedPassword != VALID_PASSWORD) {
			showError('Invalid username or password.');
			return;
		}

		showError(false);

		document.querySelector('#submit').disabled = true;

		document.querySelector('#form').submit();
	});
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
			contents += `You may log in with any password.`
		} else {
			contents += `The password <tt>` + html.EscapeString(validPassword) + `</tt> will allow you to log in; all other passwords will fail.`
		}
		contents += `
		</div>
		<div class="content">
			<div class="form">
				<h2>Login</h2>
				<div id="login-message" class="banner"></div>
				<div class="field">
					<div class="key">Username:</div>
					<div class="value"><input id="username" type="text" autofocus></div>
				</div>
				<div class="field">
					<div class="key">Password:</div>
					<div class="value"><input id="password" type="text"></div>
				</div>
				<div class="actions">
					<button id="submit">Log in</button>
				</div>
			</div>
			<form id="form" method="POST" action="` + html.EscapeString(actionURL) + `">
				<input name="SAMLRequest" type="hidden" value="` + html.EscapeString(samlRequest) + `">
				<input name="RelayState" type="hidden" value="` + html.EscapeString(relayState) + `">
			</form>
		</div>
		<div class="footer">
			On login, this will POST to: ` + html.EscapeString(actionURL) + `
		</div>
	</body>
</html>
		`
		w.Header().Add("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(contents))
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
