// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// MsgVpnClientUsername msg vpn client username
//
// swagger:model MsgVpnClientUsername
type MsgVpnClientUsername struct {

	// The ACL Profile of the Client Username. Modifying this attribute while the object (or the relevant part of the object) is administratively enabled may be service impacting as enabled will be temporarily set to false to apply the change. Changes to this attribute are synchronized to HA mates and replication sites via config-sync. The default value is `"default"`.
	ACLProfileName string `json:"aclProfileName,omitempty"`

	// The Client Profile of the Client Username. Modifying this attribute while the object (or the relevant part of the object) is administratively enabled may be service impacting as enabled will be temporarily set to false to apply the change. Changes to this attribute are synchronized to HA mates and replication sites via config-sync. The default value is `"default"`.
	ClientProfileName string `json:"clientProfileName,omitempty"`

	// The name of the Client Username.
	ClientUsername string `json:"clientUsername,omitempty"`

	// Enable or disable the Client Username. When disabled, all clients currently connected as the Client Username are disconnected. Changes to this attribute are synchronized to HA mates and replication sites via config-sync. The default value is `false`.
	Enabled bool `json:"enabled,omitempty"`

	// Enable or disable guaranteed endpoint permission override for the Client Username. When enabled all guaranteed endpoints may be accessed, modified or deleted with the same permission as the owner. Changes to this attribute are synchronized to HA mates and replication sites via config-sync. The default value is `false`.
	GuaranteedEndpointPermissionOverrideEnabled bool `json:"guaranteedEndpointPermissionOverrideEnabled,omitempty"`

	// The name of the Message VPN.
	MsgVpnName string `json:"msgVpnName,omitempty"`

	// The password for the Client Username. This attribute is absent from a GET and not updated when absent in a PUT, subject to the exceptions in note 4. Changes to this attribute are synchronized to HA mates and replication sites via config-sync. The default value is `""`.
	Password string `json:"password,omitempty"`

	// Enable or disable the subscription management capability of the Client Username. This is the ability to manage subscriptions on behalf of other Client Usernames. Changes to this attribute are synchronized to HA mates and replication sites via config-sync. The default value is `false`.
	SubscriptionManagerEnabled bool `json:"subscriptionManagerEnabled,omitempty"`
}

// Validate validates this msg vpn client username
func (m *MsgVpnClientUsername) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this msg vpn client username based on context it is used
func (m *MsgVpnClientUsername) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MsgVpnClientUsername) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MsgVpnClientUsername) UnmarshalBinary(b []byte) error {
	var res MsgVpnClientUsername
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
