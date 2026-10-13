package main

import (
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConfigureStoresPolicyData(t *testing.T) {
	policyData, err := structpb.NewStruct(map[string]interface{}{
		"approved_values": []interface{}{"data_value"},
	})
	if err != nil {
		t.Fatalf("build policy data: %v", err)
	}

	plugin := &CompliancePlugin{logger: hclog.NewNullLogger()}

	if _, err := plugin.Configure(&proto.ConfigureRequest{PolicyData: policyData}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	values, ok := plugin.policyData["approved_values"].([]interface{})
	if !ok || len(values) != 1 || values[0] != "data_value" {
		t.Fatalf("unexpected policy data: %#v", plugin.policyData)
	}

	if _, err := plugin.Configure(&proto.ConfigureRequest{}); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	if plugin.policyData != nil {
		t.Fatalf("expected policy data to be cleared, got %#v", plugin.policyData)
	}
}
