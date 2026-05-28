package main

import (
	"context"
	"fmt"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-template/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger     hclog.Logger
	config     *internal.PluginConfig
	policyData map[string]interface{}
}

// Configure, Init, and Eval are called at different times during the plugin execution lifecycle,
// and are responsible for different tasks:
//
// Configure is called on plugin startup. It is primarily used to configure a plugin for its lifetime.
// Here you should store any configurations like usernames and password required by the plugin.
//
// Init is called once for each scheduled execution with a list of policy paths and it is responsible
// for initializing any resources or registering any additional information regarding the plugin such as
// riskTemplates and subjectTemplates
//
// Eval is called once for each scheduled execution with a list of policy paths and it is responsible
// for evaluating each of these policy paths against the data it requires to evaluate those policies.
// The plugin is responsible for collecting the data it needs to evaluate the policies in the Eval
// method and then running the policies against that data.
//
// The simplest way to handle multiple policies is to do an initial lookup of all the data that may
// be required for all policies in the method, and then run the policies against that data. This,
// however, may not be the most efficient way to run policies, and you may want to optimize this
// while writing plugins to reduce the amount of data you need to collect and store in memory. It
// is the plugins responsibility to ensure that it is (reasonably) efficient in its use of
// resources.
//
// A user starts the agent, and passes the plugin and any policy bundles.
//
// The agent will:
//   - Start the plugin
//   - Call Configure() with the required config
//   - Call Init() with the required init data
//   - Call Eval() with the first policy bundles (one by one, in turn),
//     so the plugin can report any violations against the configuration
func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {

	// Configure is used to set up any configuration needed by this plugin over its lifetime.
	// This will likely only be called once on plugin startup, which may then run for an extended period of time.

	// In this method, you should save any configuration values to your plugin struct, so you can later
	// re-use them in PrepareForEval and Eval.
	rawConfig := req.GetConfig()
	parsedConfig, err := internal.ParseConfig(rawConfig)
	if err != nil {
		return nil, err
	}
	l.config = parsedConfig

	// Maps policy data for policy data.xx evaluation. This lets the agent set configuration for policy
	// execution. Uses are for overriding values like set list of tags, approved names etc.
	if req.GetPolicyData() != nil {
		l.policyData = req.GetPolicyData().AsMap()
	} else {
		l.policyData = nil
	}

	return &proto.ConfigureResponse{}, nil
}

// Init prepares plugin metadata for a scheduled execution.
//
// The agent calls Init after Configure and before Eval, passing the policy paths
// that will be evaluated for the current run. Use this method to register any
// subject templates, risk templates, or other execution-scoped metadata the
// agent needs before policy evaluation starts.
//
// When building subject templates, every label you reference in
// TitleTemplate, DescriptionTemplate, PurposeTemplate, or IdentityLabelKeys
// must also be declared in LabelSchema. If a templated key is not present in
// the schema, the agent cannot populate it correctly.
//
// The agent also adds `_plugin` automatically to the subject schema, and it
// should be treated as part of the subject identity. In practice, make sure
// your subject identity accounts for `_plugin` together with the resource-
// specific labels that uniquely identify the subject.
//
// For automation to trigger correctly, the subject Type must be
// proto.SubjectType_SUBJECT_TYPE_COMPONENT. Do not use other subject types here
// as of today, even if they appear semantically closer, because automation is
// currently built around component subjects.
//
// In this template, Init builds and returns the subject templates used by the
// policies so the agent can create consistent subjects for any evidence emitted
// during Eval.
func (l *CompliancePlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()
	subjectTemplates := []*proto.SubjectTemplate{
		{
			Name:                "ec2-instance",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "EC2 Instance {{ .resource_id }} in {{ .account_id }}/{{ .region }}",
			DescriptionTemplate: "AWS EC2 Instance {{ .resource_id }}.",
			PurposeTemplate:     "Represents an AWS EC2 instance evaluated for compliance posture.",
			IdentityLabelKeys:   []string{"account_id", "region", "resource_id"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "account_id", Description: "AWS account ID"},
				{Key: "region", Description: "AWS region"},
				{Key: "resource_id", Description: "EC2 Instance ID"},
				{Key: "resource_arn", Description: "AWS resource ARN"},
				{Key: "resource_type", Description: "EC2 normalized resource type"},
			},
		},
	}
	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.logger, req, apiHelper, subjectTemplates)
}

// Eval collects the data required for the requested policies and evaluates them.
//
// The agent calls Eval once per matching policy bundle during a scheduled
// execution. The request includes the policy paths to run, and the plugin is
// responsible for fetching the relevant source data, evaluating those policies,
// and sending any resulting evidence back through the provided API helper.
//
// In practice, this is the main execution step for the plugin: fetch data,
// evaluate `request.PolicyPaths`, and persist the produced evidence.
func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	// Eval is used to run policies against the data you've collected.
	// Eval will be called N times for every scheduled plugin execution where N is the amount of matching policies
	// passed to the agent.

	// When a user passes multiple policy bundles to the agent, each will be passed to Eval in turn to run against the
	// same data collected in PrepareForEval.

	ctx := context.Background()
	activities := make([]*proto.Activity, 0)

	if request == nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fmt.Errorf("eval request is nil")
	}

	dataFetcher := internal.NewDataFetcher(l.logger, l.config)
	data, err := dataFetcher.FetchData()
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, fmt.Errorf("failed to fetch data: %w", err)
	}

	policyEvaluator := internal.NewPolicyEvaluator(ctx, l.logger, activities)

	// Simple use case for evaluating all policies against the data collected
	evidences, err := policyEvaluator.Eval(ctx, data, request.PolicyPaths, l.policyData, l.config.PolicyLabels)

	// Advanced use case where policy bundles are filtered based on behavior
	//
	//
	// The default mapping maps plugin defined behaviours, can be extended / overwritten via agent config
	// defaultBehaviorMapping := map[string][]string{
	// 	"first-behavior-policies":  {"first"},
	// 	"second-behavior-policies": {"second"},
	// }
	// policyEval := request.WithDefaultPolicyBehavior(defaultBehaviorMapping).WithUndefinedMappedTo([]string{"first"})
	// policyPathsByBehavior := policyEval.PolicyPathsForBehavior("first")
	// evidences, err = policyEvaluator.Eval(ctx, data, policyPathsByBehavior, l.policyData, l.config.PolicyLabels)

	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, fmt.Errorf("failed to evaluate policies: %w", err)
	}

	if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
		l.logger.Error("Error creating evidence", "error", err)
		return nil, err
	}

	resp := &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}

	return resp, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("initiating plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
