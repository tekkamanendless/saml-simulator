package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/tekkamanendless/saml-simulator/samlsimulator"
)

// EnvOrBool returns the value of the environment variable; if not present or
// otherwise invalid, this returns the default value given.
func EnvOrBool(name string, defaultValue bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue
	}

	v, err := strconv.ParseBool(value)
	if err != nil {
		logrus.Warnf("Could not parse %s: %v", name, err)
		return defaultValue
	}
	return v
}

// EnvOrInt returns the value of the environment variable; if not present or
// otherwise invalid, this returns the default value given.
func EnvOrInt(name string, defaultValue int) int {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue
	}

	v, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		logrus.Warnf("Could not parse %s: %v", name, err)
		return defaultValue
	}
	return int(v)
}

// EnvOrString returns the value of the environment variable; if not present or
// otherwise invalid, this returns the default value given.
func EnvOrString(name string, defaultValue string) string {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue
	}

	return value
}

func main() {
	debug := flag.Bool("debug", EnvOrBool("DEBUG", false), "Enable this for more verbose output.\nEnvironment variable: DEBUG")
	exposeMetrics := flag.Bool("expose-metrics", EnvOrBool("EXPOSE_METRICS", false), "Enable this to expose Prometheus metrics via '/metrics'.\nEnvironment variable: EXPOSE_METRICS")
	webAddress := flag.String("web.address", EnvOrString("WEB_ADDRESS", "0.0.0.0"), "The address to listen on.\nEnvironment variable: WEB_ADDRESS")
	webPort := flag.Int("web.port", EnvOrInt("WEB_PORT", 8080), "The port number to listen on.\nEnvironment variable: WEB_PORT")
	webSSLCertFile := flag.String("web.ssl-cert", EnvOrString("WEB_SSL_CERT", ""), "The path to the SSL cert file.\nBoth this and 'web.ssl-key' must be present for HTTPS.\nEnvironment variable: WEB_SSL_CERT")
	webSSLKeyFile := flag.String("web.ssl-key", EnvOrString("WEB_SSL_KEY", ""), "The path to the SSL key file.\nBoth this and 'web.ssl-cert' must be present for HTTPS.\nEnvironment variable: WEB_SSL_KEY")
	flag.Parse()

	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.Infof("Flags:")
	logrus.Infof("* debug: %t", *debug)
	logrus.Infof("* expose-metrics: %t", *exposeMetrics)
	logrus.Infof("* web.address: %s", *webAddress)
	logrus.Infof("* web.port: %d", *webPort)
	logrus.Infof("* web.ssl-cert: %s", *webSSLCertFile)
	logrus.Infof("* web.ssl-key: %s", *webSSLKeyFile)

	listenAddress := fmt.Sprintf("%s:%d", *webAddress, *webPort)

	samlSimulator, err := samlsimulator.New()
	if err != nil {
		logrus.Errorf("Error: %v", err)
		os.Exit(1)
	}

	handler := http.NewServeMux()
	handler.Handle("/", samlSimulator)
	if *exposeMetrics {
		// Add the Prometheus metrics endpoint.
		handler.Handle("/metrics", promhttp.Handler())
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
