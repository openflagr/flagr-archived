// Code generated by go-swagger; DO NOT EDIT.

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openflagr/flagr/swagger_gen/models"
)

// FindPolicyOKCode is the HTTP code returned for type FindPolicyOK
const FindPolicyOKCode int = 200

/*FindPolicyOK evaluation result

swagger:response findPolicyOK
*/
type FindPolicyOK struct {

	/*
	  In: Body
	*/
	Payload *models.FindPolicyResponse `json:"body,omitempty"`
}

// NewFindPolicyOK creates FindPolicyOK with default headers values
func NewFindPolicyOK() *FindPolicyOK {

	return &FindPolicyOK{}
}

// WithPayload adds the payload to the find policy o k response
func (o *FindPolicyOK) WithPayload(payload *models.FindPolicyResponse) *FindPolicyOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the find policy o k response
func (o *FindPolicyOK) SetPayload(payload *models.FindPolicyResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *FindPolicyOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*FindPolicyDefault generic error response

swagger:response findPolicyDefault
*/
type FindPolicyDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Error `json:"body,omitempty"`
}

// NewFindPolicyDefault creates FindPolicyDefault with default headers values
func NewFindPolicyDefault(code int) *FindPolicyDefault {
	if code <= 0 {
		code = 500
	}

	return &FindPolicyDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the find policy default response
func (o *FindPolicyDefault) WithStatusCode(code int) *FindPolicyDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the find policy default response
func (o *FindPolicyDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the find policy default response
func (o *FindPolicyDefault) WithPayload(payload *models.Error) *FindPolicyDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the find policy default response
func (o *FindPolicyDefault) SetPayload(payload *models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *FindPolicyDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
