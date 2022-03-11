// Code generated by go-swagger; DO NOT EDIT.

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openflagr/flagr/swagger_gen/models"
)

// FindGroupPolicyOKCode is the HTTP code returned for type FindGroupPolicyOK
const FindGroupPolicyOKCode int = 200

/*FindGroupPolicyOK evaluation result

swagger:response findGroupPolicyOK
*/
type FindGroupPolicyOK struct {

	/*
	  In: Body
	*/
	Payload *models.FindGroupPolicyResponse `json:"body,omitempty"`
}

// NewFindGroupPolicyOK creates FindGroupPolicyOK with default headers values
func NewFindGroupPolicyOK() *FindGroupPolicyOK {

	return &FindGroupPolicyOK{}
}

// WithPayload adds the payload to the find group policy o k response
func (o *FindGroupPolicyOK) WithPayload(payload *models.FindGroupPolicyResponse) *FindGroupPolicyOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the find group policy o k response
func (o *FindGroupPolicyOK) SetPayload(payload *models.FindGroupPolicyResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *FindGroupPolicyOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*FindGroupPolicyDefault generic error response

swagger:response findGroupPolicyDefault
*/
type FindGroupPolicyDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Error `json:"body,omitempty"`
}

// NewFindGroupPolicyDefault creates FindGroupPolicyDefault with default headers values
func NewFindGroupPolicyDefault(code int) *FindGroupPolicyDefault {
	if code <= 0 {
		code = 500
	}

	return &FindGroupPolicyDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the find group policy default response
func (o *FindGroupPolicyDefault) WithStatusCode(code int) *FindGroupPolicyDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the find group policy default response
func (o *FindGroupPolicyDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the find group policy default response
func (o *FindGroupPolicyDefault) WithPayload(payload *models.Error) *FindGroupPolicyDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the find group policy default response
func (o *FindGroupPolicyDefault) SetPayload(payload *models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *FindGroupPolicyDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
