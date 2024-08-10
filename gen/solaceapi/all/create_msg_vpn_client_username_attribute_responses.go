// Code generated by go-swagger; DO NOT EDIT.

package all

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"kindredgroup.com/solace-plugin/gen/models"
)

// CreateMsgVpnClientUsernameAttributeReader is a Reader for the CreateMsgVpnClientUsernameAttribute structure.
type CreateMsgVpnClientUsernameAttributeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateMsgVpnClientUsernameAttributeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateMsgVpnClientUsernameAttributeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCreateMsgVpnClientUsernameAttributeDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCreateMsgVpnClientUsernameAttributeOK creates a CreateMsgVpnClientUsernameAttributeOK with default headers values
func NewCreateMsgVpnClientUsernameAttributeOK() *CreateMsgVpnClientUsernameAttributeOK {
	return &CreateMsgVpnClientUsernameAttributeOK{}
}

/*
CreateMsgVpnClientUsernameAttributeOK describes a response with status code 200, with default header values.

The Client Username Attribute object's attributes after being created, and the request metadata.
*/
type CreateMsgVpnClientUsernameAttributeOK struct {
	Payload *models.MsgVpnClientUsernameAttributeResponse
}

// IsSuccess returns true when this create msg vpn client username attribute o k response has a 2xx status code
func (o *CreateMsgVpnClientUsernameAttributeOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create msg vpn client username attribute o k response has a 3xx status code
func (o *CreateMsgVpnClientUsernameAttributeOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create msg vpn client username attribute o k response has a 4xx status code
func (o *CreateMsgVpnClientUsernameAttributeOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create msg vpn client username attribute o k response has a 5xx status code
func (o *CreateMsgVpnClientUsernameAttributeOK) IsServerError() bool {
	return false
}

// IsCode returns true when this create msg vpn client username attribute o k response a status code equal to that given
func (o *CreateMsgVpnClientUsernameAttributeOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create msg vpn client username attribute o k response
func (o *CreateMsgVpnClientUsernameAttributeOK) Code() int {
	return 200
}

func (o *CreateMsgVpnClientUsernameAttributeOK) Error() string {
	return fmt.Sprintf("[POST /msgVpns/{msgVpnName}/clientUsernames/{clientUsername}/attributes][%d] createMsgVpnClientUsernameAttributeOK  %+v", 200, o.Payload)
}

func (o *CreateMsgVpnClientUsernameAttributeOK) String() string {
	return fmt.Sprintf("[POST /msgVpns/{msgVpnName}/clientUsernames/{clientUsername}/attributes][%d] createMsgVpnClientUsernameAttributeOK  %+v", 200, o.Payload)
}

func (o *CreateMsgVpnClientUsernameAttributeOK) GetPayload() *models.MsgVpnClientUsernameAttributeResponse {
	return o.Payload
}

func (o *CreateMsgVpnClientUsernameAttributeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MsgVpnClientUsernameAttributeResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateMsgVpnClientUsernameAttributeDefault creates a CreateMsgVpnClientUsernameAttributeDefault with default headers values
func NewCreateMsgVpnClientUsernameAttributeDefault(code int) *CreateMsgVpnClientUsernameAttributeDefault {
	return &CreateMsgVpnClientUsernameAttributeDefault{
		_statusCode: code,
	}
}

/*
CreateMsgVpnClientUsernameAttributeDefault describes a response with status code -1, with default header values.

The error response.
*/
type CreateMsgVpnClientUsernameAttributeDefault struct {
	_statusCode int

	Payload *models.SempMetaOnlyResponse
}

// IsSuccess returns true when this create msg vpn client username attribute default response has a 2xx status code
func (o *CreateMsgVpnClientUsernameAttributeDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this create msg vpn client username attribute default response has a 3xx status code
func (o *CreateMsgVpnClientUsernameAttributeDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this create msg vpn client username attribute default response has a 4xx status code
func (o *CreateMsgVpnClientUsernameAttributeDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this create msg vpn client username attribute default response has a 5xx status code
func (o *CreateMsgVpnClientUsernameAttributeDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this create msg vpn client username attribute default response a status code equal to that given
func (o *CreateMsgVpnClientUsernameAttributeDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the create msg vpn client username attribute default response
func (o *CreateMsgVpnClientUsernameAttributeDefault) Code() int {
	return o._statusCode
}

func (o *CreateMsgVpnClientUsernameAttributeDefault) Error() string {
	return fmt.Sprintf("[POST /msgVpns/{msgVpnName}/clientUsernames/{clientUsername}/attributes][%d] createMsgVpnClientUsernameAttribute default  %+v", o._statusCode, o.Payload)
}

func (o *CreateMsgVpnClientUsernameAttributeDefault) String() string {
	return fmt.Sprintf("[POST /msgVpns/{msgVpnName}/clientUsernames/{clientUsername}/attributes][%d] createMsgVpnClientUsernameAttribute default  %+v", o._statusCode, o.Payload)
}

func (o *CreateMsgVpnClientUsernameAttributeDefault) GetPayload() *models.SempMetaOnlyResponse {
	return o.Payload
}

func (o *CreateMsgVpnClientUsernameAttributeDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SempMetaOnlyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}