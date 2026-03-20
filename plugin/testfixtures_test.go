package solace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// TestFixtures contains the test resources created in Solace
type TestFixtures struct {
	VPNName       string
	ACLProfile    string
	ClientProfile string
	AdminUser     string // Broker admin user for SEMP API
	AdminPwd      string // Broker admin password for SEMP API
}

// DefaultTestFixtures returns the fixture names used by tests
func DefaultTestFixtures() *TestFixtures {
	return &TestFixtures{
		VPNName:       "testvpn0",
		ACLProfile:    "test_acl_profile",
		ClientProfile: "test_client_profile",
		AdminUser:     "admin", // Broker admin for SEMP API
		AdminPwd:      "admin", // Broker admin password
	}
}

// SetupTestFixtures creates all required test resources in Solace via SEMP API
func SetupTestFixtures(sc *SolaceContainer) (*TestFixtures, error) {
	fixtures := DefaultTestFixtures()

	// Create Message VPN
	if err := createMsgVPN(sc, fixtures.VPNName); err != nil {
		return nil, fmt.Errorf("failed to create message VPN: %w", err)
	}

	// Create ACL Profile
	if err := createACLProfile(sc, fixtures.VPNName, fixtures.ACLProfile); err != nil {
		return nil, fmt.Errorf("failed to create ACL profile: %w", err)
	}

	// Create Client Profile
	if err := createClientProfile(sc, fixtures.VPNName, fixtures.ClientProfile); err != nil {
		return nil, fmt.Errorf("failed to create client profile: %w", err)
	}

	// Create test admin user (for plugin tests - NOT the container admin)
	if err := createClientUsername(sc, fixtures.VPNName, fixtures.AdminUser, fixtures.AdminPwd, fixtures.ACLProfile, fixtures.ClientProfile); err != nil {
		return nil, fmt.Errorf("failed to create admin user: %w", err)
	}

	return fixtures, nil
}

// sempRequest performs a SEMP API request
func sempRequest(sc *SolaceContainer, method, path string, body interface{}) error {
	url := fmt.Sprintf("http://%s/SEMP/v2/config%s", sc.Host, path)

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(sc.AdminUser, sc.AdminPwd)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SEMP API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// createMsgVPN creates a message VPN with basic settings enabled
func createMsgVPN(sc *SolaceContainer, vpnName string) error {
	body := map[string]interface{}{
		"msgVpnName":                 vpnName,
		"enabled":                    true,
		"authenticationBasicEnabled": true,
		"authenticationBasicType":    "internal",
		"maxMsgSpoolUsage":           1500,
		"maxConnectionCount":         100,
		"maxEgressFlowCount":         100,
		"maxIngressFlowCount":        100,
		"maxSubscriptionCount":       500000,
		"maxTransactedSessionCount":  100,
		"maxTransactionCount":        5000,
		"sempOverMsgBusAdminEnabled": true,
		"sempOverMsgBusEnabled":      true,
		"sempOverMsgBusShowEnabled":  true,
	}

	return sempRequest(sc, http.MethodPost, "/msgVpns", body)
}

// createACLProfile creates an ACL profile in the specified VPN
func createACLProfile(sc *SolaceContainer, vpnName, aclProfileName string) error {
	body := map[string]interface{}{
		"aclProfileName":                  aclProfileName,
		"msgVpnName":                      vpnName,
		"clientConnectDefaultAction":      "allow",
		"publishTopicDefaultAction":       "allow",
		"subscribeTopicDefaultAction":     "allow",
		"subscribeShareNameDefaultAction": "allow",
	}

	path := fmt.Sprintf("/msgVpns/%s/aclProfiles", vpnName)
	return sempRequest(sc, http.MethodPost, path, body)
}

// createClientProfile creates a client profile in the specified VPN
func createClientProfile(sc *SolaceContainer, vpnName, clientProfileName string) error {
	body := map[string]interface{}{
		"clientProfileName":                    clientProfileName,
		"msgVpnName":                           vpnName,
		"allowGuaranteedMsgSendEnabled":        true,
		"allowGuaranteedMsgReceiveEnabled":     true,
		"allowGuaranteedEndpointCreateEnabled": true,
		"allowTransactedSessionsEnabled":       true,
		"maxEndpointCountPerClientUsername":    100,
		"maxIngressFlowCount":                  100,
		"maxEgressFlowCount":                   100,
		"maxSubscriptionCount":                 500000,
		"maxTransactedSessionCount":            10,
		"maxTransactionCount":                  100,
	}

	path := fmt.Sprintf("/msgVpns/%s/clientProfiles", vpnName)
	return sempRequest(sc, http.MethodPost, path, body)
}

// createClientUsername creates a client username in the specified VPN
func createClientUsername(sc *SolaceContainer, vpnName, username, password, aclProfile, clientProfile string) error {
	body := map[string]interface{}{
		"clientUsername":    username,
		"msgVpnName":        vpnName,
		"password":          password,
		"enabled":           true,
		"aclProfileName":    aclProfile,
		"clientProfileName": clientProfile,
		"guaranteedEndpointPermissionOverrideEnabled": true,
		"subscriptionManagerEnabled":                  false,
	}

	path := fmt.Sprintf("/msgVpns/%s/clientUsernames", vpnName)
	return sempRequest(sc, http.MethodPost, path, body)
}

// CleanupTestFixtures removes all test resources (optional, container termination handles this)
func CleanupTestFixtures(sc *SolaceContainer, fixtures *TestFixtures) error {
	// Deleting the VPN cascades to all resources within it
	path := fmt.Sprintf("/msgVpns/%s", fixtures.VPNName)
	return sempRequest(sc, http.MethodDelete, path, nil)
}
