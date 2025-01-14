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

// DeleteMsgVpnClientUsernameReader is a Reader for the DeleteMsgVpnClientUsername structure.
type DeleteMsgVpnClientUsernameReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteMsgVpnClientUsernameReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteMsgVpnClientUsernameOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewDeleteMsgVpnClientUsernameDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewDeleteMsgVpnClientUsernameOK creates a DeleteMsgVpnClientUsernameOK with default headers values
func NewDeleteMsgVpnClientUsernameOK() *DeleteMsgVpnClientUsernameOK {
	return &DeleteMsgVpnClientUsernameOK{}
}

/*
DeleteMsgVpnClientUsernameOK describes a response with status code 200, with default header values.

The request metadata.
*/
type DeleteMsgVpnClientUsernameOK struct {
	Payload *models.SempMetaOnlyResponse
}

// IsSuccess returns true when this delete msg vpn client username o k response has a 2xx status code
func (o *DeleteMsgVpnClientUsernameOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete msg vpn client username o k response has a 3xx status code
func (o *DeleteMsgVpnClientUsernameOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete msg vpn client username o k response has a 4xx status code
func (o *DeleteMsgVpnClientUsernameOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete msg vpn client username o k response has a 5xx status code
func (o *DeleteMsgVpnClientUsernameOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete msg vpn client username o k response a status code equal to that given
func (o *DeleteMsgVpnClientUsernameOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete msg vpn client username o k response
func (o *DeleteMsgVpnClientUsernameOK) Code() int {
	return 200
}

func (o *DeleteMsgVpnClientUsernameOK) Error() string {
	return fmt.Sprintf("[DELETE /msgVpns/{msgVpnName}/clientUsernames/{clientUsername}][%d] deleteMsgVpnClientUsernameOK  %+v", 200, o.Payload)
}

func (o *DeleteMsgVpnClientUsernameOK) String() string {
	return fmt.Sprintf("[DELETE /msgVpns/{msgVpnName}/clientUsernames/{clientUsername}][%d] deleteMsgVpnClientUsernameOK  %+v", 200, o.Payload)
}

func (o *DeleteMsgVpnClientUsernameOK) GetPayload() *models.SempMetaOnlyResponse {
	return o.Payload
}

func (o *DeleteMsgVpnClientUsernameOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SempMetaOnlyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteMsgVpnClientUsernameDefault creates a DeleteMsgVpnClientUsernameDefault with default headers values
func NewDeleteMsgVpnClientUsernameDefault(code int) *DeleteMsgVpnClientUsernameDefault {
	return &DeleteMsgVpnClientUsernameDefault{
		_statusCode: code,
	}
}

/*
DeleteMsgVpnClientUsernameDefault describes a response with status code -1, with default header values.

The error response.
*/
type DeleteMsgVpnClientUsernameDefault struct {
	_statusCode int

	Payload *models.SempMetaOnlyResponse
}

// IsSuccess returns true when this delete msg vpn client username default response has a 2xx status code
func (o *DeleteMsgVpnClientUsernameDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this delete msg vpn client username default response has a 3xx status code
func (o *DeleteMsgVpnClientUsernameDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this delete msg vpn client username default response has a 4xx status code
func (o *DeleteMsgVpnClientUsernameDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this delete msg vpn client username default response has a 5xx status code
func (o *DeleteMsgVpnClientUsernameDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this delete msg vpn client username default response a status code equal to that given
func (o *DeleteMsgVpnClientUsernameDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the delete msg vpn client username default response
func (o *DeleteMsgVpnClientUsernameDefault) Code() int {
	return o._statusCode
}

func (o *DeleteMsgVpnClientUsernameDefault) Error() string {
	return fmt.Sprintf("[DELETE /msgVpns/{msgVpnName}/clientUsernames/{clientUsername}][%d] deleteMsgVpnClientUsername default  %+v", o._statusCode, o.Payload)
}

func (o *DeleteMsgVpnClientUsernameDefault) String() string {
	return fmt.Sprintf("[DELETE /msgVpns/{msgVpnName}/clientUsernames/{clientUsername}][%d] deleteMsgVpnClientUsername default  %+v", o._statusCode, o.Payload)
}

func (o *DeleteMsgVpnClientUsernameDefault) GetPayload() *models.SempMetaOnlyResponse {
	return o.Payload
}

func (o *DeleteMsgVpnClientUsernameDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SempMetaOnlyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
