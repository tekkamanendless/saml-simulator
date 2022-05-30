package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/tekkamanendless/saml-simulator/samlsimulator"
)

func main() {
	debug := flag.Bool("debug", false, "Enable this for more verbose output.")
	webAddress := flag.String("web.address", "0.0.0.0", "The address to listen on.")
	webPort := flag.Int("web.port", 8080, "The port number to listen on.")
	webSSLCertFile := flag.String("web.ssl-cert", "", "The path to the SSL cert file.  Both this and 'web.ssl-key' must be present for HTTPS.")
	webSSLKeyFile := flag.String("web.ssl-key", "", "The path to the SSL key file.  Both this and 'web.ssl-cert' must be present for HTTPS.")
	flag.Parse()

	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.Infof("Flags:")
	logrus.Infof("* debug: %t", *debug)
	logrus.Infof("* web.address: %s", *webAddress)
	logrus.Infof("* web.port: %d", *webPort)
	logrus.Infof("* web.ssl-cert: %s", *webSSLCertFile)
	logrus.Infof("* web.ssl-key: %s", *webSSLKeyFile)

	listenAddress := fmt.Sprintf("%s:%d", *webAddress, *webPort)

	handler, err := samlsimulator.New()
	if err != nil {
		logrus.Errorf("Error: %v", err)
		os.Exit(1)
	}

	if *webSSLCertFile != "" && *webSSLKeyFile != "" {
		logrus.Infof("Listening via HTTPS at %s.", listenAddress)
		err = http.ListenAndServeTLS(listenAddress, *webSSLCertFile, *webSSLKeyFile, handler)
	} else {
		logrus.Infof("Listening via HTTP at %s.", listenAddress)
		err = http.ListenAndServe(listenAddress, handler)
	}
	if err != nil {
		logrus.Errorf("Error: %v", err)
		os.Exit(1)
	}
}
