// Code generated by go-swagger; DO NOT EDIT.

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openflagr/flagr/swagger_gen/models"
)

// DeleteGroupPolicyOKCode is the HTTP code returned for type DeleteGroupPolicyOK
const DeleteGroupPolicyOKCode int = 200

/*DeleteGroupPolicyOK evaluation result

swagger:response deleteGroupPolicyOK
*/
type DeleteGroupPolicyOK struct {

	/*
	  In: Body
	*/
	Payload models.DeleteGroupPolicyResponse `json:"body,omitempty"`
}

// NewDeleteGroupPolicyOK creates DeleteGroupPolicyOK with default headers values
func NewDeleteGroupPolicyOK() *DeleteGroupPolicyOK {

	return &DeleteGroupPolicyOK{}
}

// WithPayload adds the payload to the delete group policy o k response
func (o *DeleteGroupPolicyOK) WithPayload(payload models.DeleteGroupPolicyResponse) *DeleteGroupPolicyOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete group policy o k response
func (o *DeleteGroupPolicyOK) SetPayload(payload models.DeleteGroupPolicyResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteGroupPolicyOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}

/*DeleteGroupPolicyDefault generic error response

swagger:response deleteGroupPolicyDefault
*/
type DeleteGroupPolicyDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Error `json:"body,omitempty"`
}

// NewDeleteGroupPolicyDefault creates DeleteGroupPolicyDefault with default headers values
func NewDeleteGroupPolicyDefault(code int) *DeleteGroupPolicyDefault {
	if code <= 0 {
		code = 500
	}

	return &DeleteGroupPolicyDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the delete group policy default response
func (o *DeleteGroupPolicyDefault) WithStatusCode(code int) *DeleteGroupPolicyDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the delete group policy default response
func (o *DeleteGroupPolicyDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the delete group policy default response
func (o *DeleteGroupPolicyDefault) WithPayload(payload *models.Error) *DeleteGroupPolicyDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete group policy default response
func (o *DeleteGroupPolicyDefault) SetPayload(payload *models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteGroupPolicyDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
