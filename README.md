# Compliance Framework Plugin Template

This is a template for building a compliance framework plugin.

Inspect main.go for a detailed description of how to build the plugin.

## Prerequisites

* GoReleaser https://goreleaser.com/install/

## Building

Once you are ready to serve the plugin, you need to build the binaries which can be used by the agent.

```shell
goreleaser release --snapshot --clean
```

## Usage

You can use this plugin by passing it to the compliance agent or by specifying it in the agent config

```shell
agent --plugin=[PATH_TO_YOUR_BINARY]
```

```yaml
# AGENT CONFIG

verbosity: 2

api:
  url: http://localhost:8080

plugins:
  # Plugin execution identifier
  myplugin:
    # Config mapping passed through to Configure lifecycle event
    config:
      anykey: "anyval"
      policy_labels: "{\"my_key\":\"my_value\"}"
    # Compatible protocol version: Defaults to 1, can also be determined a plugin image manifest annotation of "org.ccf.plugin.protocol.version=2"
    protocol_version: 2
    # Source to plugin executable location. Can be an OCI image or local executable
    source: /path/to/dist/plugin
    # List to all policies to pass to plugin, all may be processed or filtered later via policy_behavior
    policies:
       - /path/to/policy/bundle.tar.gz
    # Policy behaviour can be defined to later filter policies to specific bundles per execution
    # This is useful if your plugin proccesses more than 1 type of component
    policy_behavior:
      string-to-match-to-policy:
        - "associated-behavior-1"
    # Policy data is passed to the plugin for evaluation, can be used to customize evaluation parameters
    policy_data:
      policy_data_key: "policy_data_value"
        

```

You can also use `make run` to build this plugin and execute against the agent, if the agent is located in the parent directory. See Makefile:run

