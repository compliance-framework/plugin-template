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
  myplugin:
    config:
      anykey: "anyval"
    protocol_version: 2
    source: /path/to/dist/plugin
    policies:
       - /path/to/policy/bundle.tar.gz

```

You can also use `make run` to build this plugin and execute against the agent, if the agent is located in the parent directory. See Makefile:run

