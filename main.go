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

	evidences, err := policyEvaluator.Eval(ctx, data, request.PolicyPaths, l.policyData, nil)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, fmt.Errorf("failed to evaluate policies: %w", err)
	}

	if err != nil {
		l.logger.Error("Error evaluating policies", "error", err)
		return nil, err
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
