package internal

import (
	"context"
	"errors"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

type PolicyEvaluator struct {
	ctx            context.Context
	logger         hclog.Logger
	stepActivities []*proto.Activity
}

func NewPolicyEvaluator(ctx context.Context, logger hclog.Logger, stepActivities []*proto.Activity) *PolicyEvaluator {
	return &PolicyEvaluator{
		ctx:            ctx,
		logger:         logger,
		stepActivities: stepActivities,
	}
}

// Eval is used to run policies against the data you've collected. You could also consider an
// `EvalAndSend` by passing in the `apiHelper` that sends the observations directly to the API.
func (pe *PolicyEvaluator) Eval(ctx context.Context, input map[string]interface{}, policyPaths []string, policyData map[string]interface{}, labels map[string]string) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	evidences := make([]*proto.Evidence, 0)
	activities := pe.stepActivities

	for _, policyPath := range policyPaths {
		steps := make([]*proto.Step, 0)
		steps = append(steps, &proto.Step{
			Title:       "Compile policy bundle",
			Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
		})
		steps = append(steps, &proto.Step{
			Title:       "Execute policy bundle",
			Description: "Using previously collected JSON-formatted installed OS package data, execute the compiled policies",
		})
		// The Policy Manager aggregates much of the policy execution and output structuring.
		processor := policyManager.NewPolicyProcessor(
			pe.logger,
			MergeMaps(labels, map[string]string{
				"provider":         "my_plugin",
				"additional_label": "value",
			}),
			[]*proto.Subject{},
			[]*proto.Component{},
			[]*proto.InventoryItem{},
			[]*proto.OriginActor{},
			activities,
			policyData,
		)

		evidence, perr := processor.GenerateResults(ctx, policyPath, input)
		evidences = append(evidences, evidence...)
		if perr != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, perr)
		}
	}

	return evidences, accumulatedErrors
}
