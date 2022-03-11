package handler

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/openflagr/flagr/pkg/entity"
	"github.com/openflagr/flagr/pkg/util"
	"github.com/openflagr/flagr/swagger_gen/models"
	"github.com/openflagr/flagr/swagger_gen/restapi/operations/policy"
)

func CreatePolicy(params policy.CreatePolicyParams) middleware.Responder {
	if params.Body == nil {
		return policy.NewCreatePolicyDefault(400).WithPayload(ErrorMessage("body was nil"))
	}

	added, err := entity.GetRBACController().Enforcer.AddPolicy(*params.Body.Subject, *params.Body.Object, *params.Body.Action)
	if err != nil {
		return policy.NewCreatePolicyDefault(500).WithPayload(
			ErrorMessage("failed to create policy: %s", err))
	}

	if !added {
		return policy.NewCreatePolicyDefault(202).WithPayload(ErrorMessage("policy already exists"))
	}

	return policy.NewCreatePolicyOK()
}

func PutPolicy(params policy.PutPolicyParams) middleware.Responder {
	if params.Body == nil {
		return policy.NewPutPolicyDefault(400).WithPayload(ErrorMessage("body was nil"))
	}

	updated, err := entity.GetRBACController().Enforcer.UpdatePolicy(
		[]string{*params.Body.OldPolicy.Subject, *params.Body.OldPolicy.Object, *params.Body.OldPolicy.Action},
		[]string{*params.Body.NewPolicy.Subject, *params.Body.NewPolicy.Object, *params.Body.NewPolicy.Action},
	)
	if err != nil {
		return policy.NewPutPolicyDefault(500).WithPayload(
			ErrorMessage("failed to create policy: %s", err))
	}

	if !updated {
		return policy.NewPutPolicyDefault(404).WithPayload(ErrorMessage("policy doesn't exist"))
	}

	return policy.NewPutPolicyOK()
}

func DeletePolicy(params policy.DeletePolicyParams) middleware.Responder {
	if params.Body == nil {
		return policy.NewDeletePolicyDefault(400).WithPayload(ErrorMessage("body was nil"))
	}

	deleted, err := entity.GetRBACController().Enforcer.RemovePolicy(*params.Body.Subject, *params.Body.Object, *params.Body.Action)
	if err != nil {
		return policy.NewDeletePolicyDefault(500).WithPayload(
			ErrorMessage("failed to delete policy: %s", err))
	}

	if !deleted {
		return policy.NewDeletePolicyDefault(404).WithPayload(ErrorMessage("policy doesn't exist"))
	}

	return policy.NewDeletePolicyOK()
}

func FindPolicies(params policy.FindPolicyParams) middleware.Responder {
	var subjectFilter, objectFilter, actionFilter string

	if params.Body != nil {
		subjectFilter, objectFilter, actionFilter = params.Body.Subject, params.Body.Object, params.Body.Action
	}

	policies := entity.GetRBACController().Enforcer.GetFilteredPolicy(0, subjectFilter, objectFilter, actionFilter)

	result := &models.FindPolicyResponse{
		Policies: make([]*models.Policy, 0, len(policies)),
	}

	for _, policy := range policies {
		result.Policies = append(result.Policies, &models.Policy{
			Subject: util.StringPtr(policy[0]),
			Object:  util.StringPtr(policy[1]),
			Action:  util.StringPtr(policy[2]),
		})
	}

	response := policy.NewFindPolicyOK()
	response.SetPayload(result)

	return response
}

func CreateGroupPolicy(params policy.CreateGroupPolicyParams) middleware.Responder {
	if params.Body == nil {
		return policy.NewCreateGroupPolicyDefault(400).WithPayload(ErrorMessage("body was nil"))
	}

	added, err := entity.GetRBACController().Enforcer.AddGroupingPolicy(*params.Body.Subject, *params.Body.Group)
	if err != nil {
		return policy.NewCreateGroupPolicyDefault(500).WithPayload(ErrorMessage("failed to create group policy: %s", err))
	}

	if !added {
		return policy.NewCreateGroupPolicyDefault(202).WithPayload(ErrorMessage("group policy already exists"))
	}

	return policy.NewCreateGroupPolicyOK()
}

func PutGroupPolicy(params policy.PutGroupPolicyParams) middleware.Responder {
	if params.Body == nil {
		return policy.NewPutGroupPolicyDefault(400).WithPayload(ErrorMessage("body was nil"))
	}

	updated, err := entity.GetRBACController().Enforcer.UpdateGroupingPolicy(
		[]string{*params.Body.OldPolicy.Subject, *params.Body.OldPolicy.Group},
		[]string{*params.Body.NewPolicy.Subject, *params.Body.NewPolicy.Group},
	)
	if err != nil {
		return policy.NewPutGroupPolicyDefault(500).WithPayload(ErrorMessage("failed to update group policy: %s", err))
	}

	if !updated {
		return policy.NewPutGroupPolicyDefault(404).WithPayload(ErrorMessage("group policy does not exist"))
	}

	return policy.NewPutGroupPolicyOK()
}

func DeleteGroupPolicy(params policy.DeleteGroupPolicyParams) middleware.Responder {
	if params.Body == nil {
		return policy.NewDeleteGroupPolicyDefault(400).WithPayload(ErrorMessage("body was nil"))
	}

	deleted, err := entity.GetRBACController().Enforcer.RemoveGroupingPolicy(*params.Body.Subject, *params.Body.Group)
	if err != nil {
		return policy.NewDeleteGroupPolicyDefault(500).WithPayload(ErrorMessage("failed to update group policy: %s", err))
	}

	if !deleted {
		return policy.NewDeleteGroupPolicyDefault(404).WithPayload(ErrorMessage("group policy does not exist"))
	}

	return policy.NewDeleteGroupPolicyOK()
}

func FindGroupPolicies(params policy.FindGroupPolicyParams) middleware.Responder {
	var groupFilter, subjectFilter string

	if params.Body != nil {
		groupFilter, subjectFilter = params.Body.Group, params.Body.Subject
	}

	policies := entity.GetRBACController().Enforcer.GetFilteredGroupingPolicy(0, subjectFilter, groupFilter)

	result := &models.FindGroupPolicyResponse{
		Policies: make([]*models.GroupPolicy, 0, len(policies)),
	}

	for _, policy := range policies {
		result.Policies = append(result.Policies, &models.GroupPolicy{
			Group:   util.StringPtr(policy[0]),
			Subject: util.StringPtr(policy[1]),
		})
	}

	response := policy.NewFindGroupPolicyOK()
	response.SetPayload(result)

	return response
}
