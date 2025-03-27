package internal

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type PolicyEvaluator struct {
	ctx            context.Context
	logger         hclog.Logger
	stepActivities []*proto.Activity
	observations   []*proto.Observation
	findings       []*proto.Finding
}

func NewPolicyEvaluator(ctx context.Context, logger hclog.Logger, stepActivities []*proto.Activity) *PolicyEvaluator {
	return &PolicyEvaluator{
		ctx:            ctx,
		logger:         logger,
		stepActivities: stepActivities,
		observations:   make([]*proto.Observation, 0),
		findings:       make([]*proto.Finding, 0),
	}
}

func (pe *PolicyEvaluator) GetObservations() []*proto.Observation {
	return pe.observations
}

func (pe *PolicyEvaluator) GetFindings() []*proto.Finding {
	return pe.findings
}

// Eval is used to run policies against the data you've collected. You could also consider an
// `EvalAndSend` by passing in the `apiHelper` that sends the observations directly to the API.
func (pe *PolicyEvaluator) Eval(data map[string]interface{}, policyPaths []string) (proto.ExecutionStatus, error) {
	var accumulatedErrors error
	activities := pe.stepActivities

	evalStatus := proto.ExecutionStatus_SUCCESS
	startTime := time.Now()

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
		results, err := policyManager.New(pe.ctx, pe.logger, policyPath).Execute(pe.ctx, "compliance_plugin", data)
		if err != nil {
			pe.logger.Error("Failed to evaluate against policy bundle", "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			continue
		}

		// The plugin should pass in some parameters here that will uniquely identify the subject.
		// This could be a hostname in the case it's a machine, the identifier of a cloud resource, etc.
    hostname, err := os.Hostname()
    if err != nil {
        hostname = "fallback-val"
    }
		subjectAttributeMap := map[string]string{
			"type":     "machine-instance",
			"hostname": hostname,
		}
		subjects := []*proto.SubjectReference{
			{
				Type:       "machine-instance",
				Attributes: subjectAttributeMap,
				Title:      StringAddressed("Machine Instance"),
				Remarks:    StringAddressed("A machine instance where we've retrieved the installed packages."),
				Props: []*proto.Property{
					{
						Name:    "hostname",
						Value:   hostname,
						Remarks: StringAddressed("The local hostname of the machine where the plugin has been executed"),
					},
				},
			},
		}
		actors := []*proto.OriginActor{
			{
				Title: "The Continuous Compliance Framework",
				Type:  "assessment-platform",
				Links: []*proto.Link{
					{
						Href: "https://compliance-framework.github.io/docs/",
						Rel:  StringAddressed("reference"),
						Text: StringAddressed("The Continuous Compliance Framework"),
					},
				},
				Props: nil,
			},
			{
				Title: "Continuous Compliance Framework - Local APT Installed Packages Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-apt-versions",
						Rel:  StringAddressed("reference"),
						Text: StringAddressed("The Continuous Compliance Framework' Local APT Installed Packages Plugin"),
					},
				},
				Props: nil,
			},
		}
		components := []*proto.ComponentReference{
			{
				Identifier: "common-components/template",
			},
		}

		activities = append(activities, &proto.Activity{
			Title:       "Compile Results",
			Description: "Using the output from policy execution, compile the resulting output to Observations and Findings, marking any violations, risks, and other OSCAL-familiar data",
			Steps:       steps,
		})

		for _, result := range results {
			// Observation UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
			// This acts as an identifier to show the history of an observation.
			observationUUIDMap := map[string]string{
				"policy":      result.Policy.Package.PurePackage(),
				"policy_file": result.Policy.File,
				"policy_path": policyPath,
			}
			maps.Copy(subjectAttributeMap, observationUUIDMap)
			observationUUID, err := sdk.SeededUUID(observationUUIDMap)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				// We've been unable to do much here, but let's try the next one regardless.
				continue
			}

			// Finding UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
			// This acts as an identifier to show the history of a finding.
			findingUUIDMap := map[string]string{
				"policy":      result.Policy.Package.PurePackage(),
				"policy_file": result.Policy.File,
				"policy_path": policyPath,
			}
			maps.Copy(subjectAttributeMap, findingUUIDMap)
			findingUUID, err := sdk.SeededUUID(findingUUIDMap)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				// We've been unable to do much here, but let's try the next one regardless.
				continue
			}

			observation := proto.Observation{
				ID:         uuid.New().String(),
				UUID:       observationUUID.String(),
				Collected:  timestamppb.New(startTime),
				Expires:    timestamppb.New(startTime.Add(24 * time.Hour)),
				Origins:    []*proto.Origin{{Actors: actors}},
				Subjects:   subjects,
				Activities: activities,
				Components: components,
				RelevantEvidence: []*proto.RelevantEvidence{
					{
						Description: fmt.Sprintf("Policy %v was executed against the Local SSH configuration, using the Local SSH Compliance Plugin", result.Policy.Package.PurePackage()),
					},
				},
			}

			newFinding := func() *proto.Finding {
				return &proto.Finding{
					ID:        uuid.New().String(),
					UUID:      findingUUID.String(),
					Collected: timestamppb.New(time.Now()),
					Labels: map[string]string{
						"type":         "ssh",
						"host":         hostname,
						"_policy":      result.Policy.Package.PurePackage(),
						"_policy_path": result.Policy.File,
					},
					Origins:             []*proto.Origin{{Actors: actors}},
					Subjects:            subjects,
					Components:          components,
					RelatedObservations: []*proto.RelatedObservation{{ObservationUUID: observation.ID}},
					Controls:            nil,
				}
			}

			if len(result.Violations) == 0 {
				observation.Title = StringAddressed(fmt.Sprintf("Plugin validation on %s passed.", result.Policy.Package.PurePackage()))
				observation.Description = fmt.Sprintf("Observed no violations on the %s policy within the Template Compliance Plugin.", result.Policy.Package.PurePackage())
				pe.observations = append(pe.observations, &observation)

				finding := newFinding()
				finding.Title = fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())
				finding.Description = fmt.Sprintf("No violations found on the %s policy within the Template Compliance Plugin.", result.Policy.Package.PurePackage())
				finding.Status = &proto.FindingStatus{
					State: runner.FindingTargetStatusSatisfied,
				}
				pe.findings = append(pe.findings, finding)
			} else {
				observation.Title = StringAddressed(fmt.Sprintf("The plugin found violations for policy %s.", result.Policy.Package.PurePackage()))
				observation.Description = fmt.Sprintf("Observed %d violation(s) on the %s policy within the Template Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage())
				pe.observations = append(pe.observations, &observation)

				for _, violation := range result.Violations {
					finding := newFinding()
					finding.Title = violation.Title
					finding.Description = violation.Description
					finding.Remarks = StringAddressed(violation.Remarks)
					finding.Status = &proto.FindingStatus{
						State: runner.FindingTargetStatusNotSatisfied,
					}
					pe.findings = append(pe.findings, finding)
				}
			}
		}
	}

	return evalStatus, accumulatedErrors
}
