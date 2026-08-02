#!/bin/sh
set -eu

binary="${LATCH_BINARY:-${RUNNER_TEMP:?RUNNER_TEMP is required}/latch/bin/latch}"
if [ ! -x "$binary" ]; then
  echo "::error title=Latch policy gate::Trusted Latch binary is unavailable or not executable"
  exit 1
fi

set -- ci \
  --provider github \
  --config "${LATCH_CONFIG_INPUT:?config is required}" \
  --agent "${LATCH_AGENT_INPUT:?agent is required}" \
  --tool "${LATCH_TOOL_INPUT:?tool is required}" \
  --arguments-json-env LATCH_ARGUMENTS_INPUT \
  --json

if [ -n "${LATCH_OPERATION_INPUT:-}" ]; then
  set -- "$@" --action "$LATCH_OPERATION_INPUT"
fi
if [ -n "${LATCH_RESOURCE_INPUT:-}" ]; then
  set -- "$@" --resource "$LATCH_RESOURCE_INPUT"
fi

exec "$binary" "$@"
