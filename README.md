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

You can use this plugin by passing it to the compliiance agent

```shell
agent --plugin=[PATH_TO_YOUR_BINARY]
```

## Releasing

Once you are ready to release your plugin, you need only create a release in Github, and the plugin binaries
will be added as artifacts on the release page

