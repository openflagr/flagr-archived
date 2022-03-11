// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// FindGroupPolicyContext find group policy context
//
// swagger:model findGroupPolicyContext
type FindGroupPolicyContext struct {

	// group
	Group string `json:"group,omitempty"`

	// subject
	Subject string `json:"subject,omitempty"`
}

// Validate validates this find group policy context
func (m *FindGroupPolicyContext) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this find group policy context based on context it is used
func (m *FindGroupPolicyContext) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FindGroupPolicyContext) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FindGroupPolicyContext) UnmarshalBinary(b []byte) error {
	var res FindGroupPolicyContext
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
