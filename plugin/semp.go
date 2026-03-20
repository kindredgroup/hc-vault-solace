package solace

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/clbanning/mxj/v2"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	hclog "github.com/hashicorp/go-hclog"
	all "kindredgroup.com/solace-plugin/gen/solaceapi/all"
)

const (
	sempV1Path          = "/SEMP"
	msgSpoolXMLRequest  = "<rpc><show><message-spool/></show></rpc>"
	configStatusKey     = "config-status"
	configStatusPrimary = "Enabled (Primary)"
)

// getSchemes returns the URL schemes to use based on TLS configuration.
// Returns ["http"] if TLS is disabled, ["http", "https"] otherwise.
func getSchemes(cfg *solaceConfig) []string {
	if cfg.DisableTLS {
		return []string{"http"}
	}
	return []string{"http", "https"}
}

// getScheme returns a single URL scheme based on TLS configuration.
func getScheme(cfg *solaceConfig) string {
	if cfg.DisableTLS {
		return "http"
	}
	return "https"
}

// getClient returns SEMP v2 client
func getClient(cfg *solaceConfig, logger hclog.Logger) (all.ClientService, error) {
	hosts := strings.Split(cfg.SolaceHost, ",")
	logger.Debug("getClient", "hosts", hclog.Fmt("%v", hosts))

	var host string
	// SolaceConfig can't be persisted without the hostname, so no default case here
	if len(hosts) > 1 {
		host = getPrimary(hosts, cfg, logger)
		if host == "" {
			return nil, errors.New("getPrimary returned nil")
		}
	} else {
		host = hosts[0]
	}
	transport := httptransport.New(host, cfg.SolacePath, getSchemes(cfg))
	return all.New(transport, strfmt.Default), nil
}

// getPrimary loops through list of the Solace hosts and returns the active one
func getPrimary(hosts []string, cfg *solaceConfig, logger hclog.Logger) string {
	logger.Debug("getPrimary", "hosts", hclog.Fmt("%v", hosts))
	for _, host := range hosts {
		if isActive(host, cfg, logger) {
			return host
		}
		logger.Debug("getPrimary", "debug", hclog.Fmt("%s is not active or check failed", host))
	}
	logger.Error("getPrimary", "error", hclog.Fmt("could not find primary host, hosts = %v", hosts))
	return ""
}

// isActive tries to figure out if Solace box is active in HA setup. It uses SEMP v1 since
// message spool info isn't exposed through v2 at the moment. solaceConfig is used for the
// credentials and TLS toggle, SolaceHost is ignored. It logs some errors at info level
// since errors from non-operational host might be confusing.
func isActive(host string, cfg *solaceConfig, logger hclog.Logger) bool {
	logger.Debug("Host: " + host)

	req, err := newSEMPv1Request(host, cfg, msgSpoolXMLRequest)
	if err != nil {
		logger.Info("isActive", "error creating request", err.Error())
		return false
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Info("isActive", "error while talking to Solace", err.Error())
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Info("isActive", "Got response code", resp.Status)
		return false
	}

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("isActive", "error while reading response body", err.Error())
		return false
	}

	isPrimary, err := parseConfigStatus(out)
	if err != nil {
		logger.Error("isActive", "error parsing config status", err.Error())
		return false
	}

	if !isPrimary {
		logger.Debug("isActive", "message spool status", "not primary")
	}
	return isPrimary
}

// parseConfigStatus parses SEMP v1 XML response and returns true if the broker is primary.
func parseConfigStatus(xmlData []byte) (bool, error) {
	sp, err := mxj.NewMapXml(xmlData)
	if err != nil {
		return false, fmt.Errorf("error parsing XML: %w", err)
	}

	configStatus, err := sp.ValuesForKey(configStatusKey)
	if err != nil {
		return false, fmt.Errorf("error getting config-status key: %w", err)
	}

	if len(configStatus) == 0 {
		return false, errors.New("config-status not found in response")
	}

	status, ok := configStatus[0].(string)
	if !ok {
		return false, fmt.Errorf("config-status is not a string: %T", configStatus[0])
	}

	return status == configStatusPrimary, nil
}

// newSEMPv1Request creates an HTTP request for SEMP v1 API calls
func newSEMPv1Request(host string, cfg *solaceConfig, body string) (*http.Request, error) {
	reqURL := &url.URL{
		Scheme: getScheme(cfg),
		Host:   host,
		Path:   sempV1Path,
		User:   url.UserPassword(cfg.SolaceUser, cfg.SolacePwd),
	}

	req := &http.Request{
		Method: http.MethodPost,
		URL:    reqURL,
		Body:   io.NopCloser(strings.NewReader(body)),
	}

	return req, nil
}
