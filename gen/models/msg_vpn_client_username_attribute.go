// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// MsgVpnClientUsernameAttribute msg vpn client username attribute
//
// swagger:model MsgVpnClientUsernameAttribute
type MsgVpnClientUsernameAttribute struct {

	// The name of the Attribute.
	AttributeName string `json:"attributeName,omitempty"`

	// The value of the Attribute.
	AttributeValue string `json:"attributeValue,omitempty"`

	// The name of the Client Username.
	ClientUsername string `json:"clientUsername,omitempty"`

	// The name of the Message VPN.
	MsgVpnName string `json:"msgVpnName,omitempty"`
}

// Validate validates this msg vpn client username attribute
func (m *MsgVpnClientUsernameAttribute) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this msg vpn client username attribute based on context it is used
func (m *MsgVpnClientUsernameAttribute) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *MsgVpnClientUsernameAttribute) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *MsgVpnClientUsernameAttribute) UnmarshalBinary(b []byte) error {
	var res MsgVpnClientUsernameAttribute
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
