// Code generated by go-swagger; DO NOT EDIT.

package system_information

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetSystemInformationParams creates a new GetSystemInformationParams object
// with the default values initialized.
func NewGetSystemInformationParams() *GetSystemInformationParams {

	return &GetSystemInformationParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetSystemInformationParamsWithTimeout creates a new GetSystemInformationParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetSystemInformationParamsWithTimeout(timeout time.Duration) *GetSystemInformationParams {

	return &GetSystemInformationParams{

		timeout: timeout,
	}
}

// NewGetSystemInformationParamsWithContext creates a new GetSystemInformationParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetSystemInformationParamsWithContext(ctx context.Context) *GetSystemInformationParams {

	return &GetSystemInformationParams{

		Context: ctx,
	}
}

// NewGetSystemInformationParamsWithHTTPClient creates a new GetSystemInformationParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetSystemInformationParamsWithHTTPClient(client *http.Client) *GetSystemInformationParams {

	return &GetSystemInformationParams{
		HTTPClient: client,
	}
}

/*GetSystemInformationParams contains all the parameters to send to the API endpoint
for the get system information operation typically these are written to a http.Request
*/
type GetSystemInformationParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get system information params
func (o *GetSystemInformationParams) WithTimeout(timeout time.Duration) *GetSystemInformationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get system information params
func (o *GetSystemInformationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get system information params
func (o *GetSystemInformationParams) WithContext(ctx context.Context) *GetSystemInformationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get system information params
func (o *GetSystemInformationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get system information params
func (o *GetSystemInformationParams) WithHTTPClient(client *http.Client) *GetSystemInformationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get system information params
func (o *GetSystemInformationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetSystemInformationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
