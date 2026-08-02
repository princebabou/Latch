$ErrorActionPreference = "Stop"

$binary = $env:LATCH_BINARY
if ([string]::IsNullOrWhiteSpace($binary)) {
    if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
        throw "Latch policy gate: RUNNER_TEMP is required"
    }
    $binary = Join-Path $env:RUNNER_TEMP "latch\bin\latch.exe"
}
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    Write-Output "::error title=Latch policy gate::Trusted Latch binary is unavailable"
    exit 1
}
if ([string]::IsNullOrWhiteSpace($env:LATCH_CONFIG_INPUT) -or
    [string]::IsNullOrWhiteSpace($env:LATCH_AGENT_INPUT) -or
    [string]::IsNullOrWhiteSpace($env:LATCH_TOOL_INPUT)) {
    Write-Output "::error title=Latch policy gate::config, agent, and tool are required"
    exit 64
}

$arguments = @(
    "ci",
    "--provider", "github",
    "--config", $env:LATCH_CONFIG_INPUT,
    "--agent", $env:LATCH_AGENT_INPUT,
    "--tool", $env:LATCH_TOOL_INPUT,
    "--arguments-json-env", "LATCH_ARGUMENTS_INPUT",
    "--json"
)
if (-not [string]::IsNullOrWhiteSpace($env:LATCH_OPERATION_INPUT)) {
    $arguments += @("--action", $env:LATCH_OPERATION_INPUT)
}
if (-not [string]::IsNullOrWhiteSpace($env:LATCH_RESOURCE_INPUT)) {
    $arguments += @("--resource", $env:LATCH_RESOURCE_INPUT)
}

& $binary @arguments
exit $LASTEXITCODE
