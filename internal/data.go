package internal

import (
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

type DataFetcher struct {
	logger hclog.Logger
	config *PluginConfig
}

func NewDataFetcher(logger hclog.Logger, config *PluginConfig) *DataFetcher {
	return &DataFetcher{
		logger: logger,
		config: config,
	}
}

func (df DataFetcher) FetchData() (map[string]any, error) {
	steps := make([]*proto.Step, 0)

	steps = append(steps, &proto.Step{
		Title:       "Fetch some data",
		Description: "Fetch some data with more details. This should be replaced with the detailed steps you undertake to fetch data in your actual plugin.",
		Remarks:     StringAddressed("Put any remarks here"),
	})

	return map[string]any{
		"data_key":   "data_value",
		"data_key_2": "data_value_2",
	}, nil
}
