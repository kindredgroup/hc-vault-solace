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

// CreateMsgVpnClientUsernameReader is a Reader for the CreateMsgVpnClientUsername structure.
type CreateMsgVpnClientUsernameReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateMsgVpnClientUsernameReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateMsgVpnClientUsernameOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCreateMsgVpnClientUsernameDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCreateMsgVpnClientUsernameOK creates a CreateMsgVpnClientUsernameOK with default headers values
func NewCreateMsgVpnClientUsernameOK() *CreateMsgVpnClientUsernameOK {
	return &CreateMsgVpnClientUsernameOK{}
}

/*
CreateMsgVpnClientUsernameOK describes a response with status code 200, with default header values.

The Client Username object's attributes after being created, and the request metadata.
*/
type CreateMsgVpnClientUsernameOK struct {
	Payload *models.MsgVpnClientUsernameResponse
}

// IsSuccess returns true when this create msg vpn client username o k response has a 2xx status code
func (o *CreateMsgVpnClientUsernameOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create msg vpn client username o k response has a 3xx status code
func (o *CreateMsgVpnClientUsernameOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create msg vpn client username o k response has a 4xx status code
func (o *CreateMsgVpnClientUsernameOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create msg vpn client username o k response has a 5xx status code
func (o *CreateMsgVpnClientUsernameOK) IsServerError() bool {
	return false
}

// IsCode returns true when this create msg vpn client username o k response a status code equal to that given
func (o *CreateMsgVpnClientUsernameOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create msg vpn client username o k response
func (o *CreateMsgVpnClientUsernameOK) Code() int {
	return 200
}

func (o *CreateMsgVpnClientUsernameOK) Error() string {
	return fmt.Sprintf("[POST /msgVpns/{msgVpnName}/clientUsernames][%d] createMsgVpnClientUsernameOK  %+v", 200, o.Payload)
}

func (o *CreateMsgVpnClientUsernameOK) String() string {
	return fmt.Sprintf("[POST /msgVpns/{msgVpnName}/clientUsernames][%d] createMsgVpnClientUsernameOK  %+v", 200, o.Payload)
}

func (o *CreateMsgVpnClientUsernameOK) GetPayload() *models.MsgVpnClientUsernameResponse {
	return o.Payload
}

func (o *CreateMsgVpnClientUsernameOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MsgVpnClientUsernameResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateMsgVpnClientUsernameDefault creates a CreateMsgVpnClientUsernameDefault with default headers values
func NewCreateMsgVpnClientUsernameDefault(code int) *CreateMsgVpnClientUsernameDefault {
	return &CreateMsgVpnClientUsernameDefault{
		_statusCode: code,
	}
}

/*
CreateMsgVpnClientUsernameDefault describes a response with status code -1, with default header values.

The error response.
*/
type CreateMsgVpnClientUsernameDefault struct {
	_statusCode int

	Payload *models.SempMetaOnlyResponse
}

// IsSuccess returns true when this create msg vpn client username default response has a 2xx status code
func (o *CreateMsgVpnClientUsernameDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this create msg vpn client username default response has a 3xx status code
func (o *CreateMsgVpnClientUsernameDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this create msg vpn client username default response has a 4xx status code
func (o *CreateMsgVpnClientUsernameDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this create msg vpn client username default response has a 5xx status code
func (o *CreateMsgVpnClientUsernameDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this create msg vpn client username default response a status code equal to that given
func (o *CreateMsgVpnClientUsernameDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the create msg vpn client username default response
func (o *CreateMsgVpnClientUsernameDefault) Code() int {
	return o._statusCode
}

func (o *CreateMsgVpnClientUsernameDefault) Error() string {
	return fmt.Sprintf("[POST /msgVpns/{msgVpnName}/clientUsernames][%d] createMsgVpnClientUsername default  %+v", o._statusCode, o.Payload)
}

func (o *CreateMsgVpnClientUsernameDefault) String() string {
	return fmt.Sprintf("[POST /msgVpns/{msgVpnName}/clientUsernames][%d] createMsgVpnClientUsername default  %+v", o._statusCode, o.Payload)
}

func (o *CreateMsgVpnClientUsernameDefault) GetPayload() *models.SempMetaOnlyResponse {
	return o.Payload
}

func (o *CreateMsgVpnClientUsernameDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SempMetaOnlyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}