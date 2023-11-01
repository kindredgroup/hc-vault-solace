package solace

import (
	"errors"
	"github.com/clbanning/mxj/v2"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	hclog "github.com/hashicorp/go-hclog"
	"io"
	"io/ioutil"
	all "kindredgroup.com/solace-plugin/gen/solaceapi/all"
	"net/http"
	"net/url"
	"strings"
)

// getClient returns SEMP v2 client
func getClient(cfg *solaceConfig, logger hclog.Logger) (all.ClientService, error) {
	accessSchemes := []string{"http", "https"}
	if cfg.DisableTls {
		accessSchemes = []string{"http"}
	}
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
	transport := httptransport.New(host, cfg.SolacePath, accessSchemes)
	return all.New(transport, strfmt.Default), nil

}

// getPrimary loops throug list of the Solace hosts and returns the active one
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
// credentials and TLS toggle, SolaceHost is ignored. Is logs some errors in info level
// since errors from non-operational host might be confusing.
func isActive(host string, cfg *solaceConfig, logger hclog.Logger) bool {
	var scheme string
	logger.Debug("Host: " + host)
	if cfg.DisableTls {
		scheme = "http"
	} else {
		scheme = "https"
	}
	client := &http.Client{}
	url := &url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   "/SEMP",
		User:   url.UserPassword(cfg.SolaceUser, cfg.SolacePwd),
	}
	// Another way to get the redundancy is '<rpc><show><redundancy/></show></rpc>'
	// virtual-routers/primary/status/activity returns the redundancy state of the primary
	// broker. If != 'Local Active' then another one is the primary.
	bodice := strings.NewReader("<rpc><show><message-spool/></show></rpc>")
	request := &http.Request{Method: http.MethodPost,
		URL:  url,
		Body: io.NopCloser(bodice),
	}
	resp, err := client.Do(request)
	if err != nil {
		logger.Info("isActive", "error while talking to Solace", err.Error())
		return false
	}
	if !strings.HasPrefix(resp.Status, "200") {
		logger.Info("isActive", "Got response code", resp.Status)
		return false
	}
	out, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error("isActive", "error while reading response body", err.Error())
		return false
	}
	sp, err := mxj.NewMapXml(out)
	if err != nil {
		logger.Error("isActive", "error parsing XML", err.Error())
		return false
	}
	configStatus, err := sp.ValuesForKey("config-status")
	if err != nil {
		logger.Error(err.Error())
		return false
	}
	if (configStatus[0].(string)) == "Enabled (Primary)" {
		return true
	}
	logger.Debug("Message spool status: " + configStatus[0].(string))
	return false
}
