# Latch Go SDK

```go
client, err := latch.New("http://127.0.0.1:7070", latch.WithToken(os.Getenv("LATCH_API_TOKEN")))
if err != nil {
    return err
}

decision, err := client.Decide(ctx, v1.Action{
    Tool: "filesystem.read",
    Arguments: map[string]any{"path": "./README.md"},
})
if err != nil {
    return err // fail closed
}
if decision.Decision != models.DecisionAllow {
    return fmt.Errorf("action not allowed: %s", decision.Decision)
}
```

For short tool wrappers, `Guard` invokes the callback only after an explicit,
valid `ALLOW`. Connection failures, timeouts, redirects, oversized responses,
malformed JSON, version mismatches, `BLOCK`, and `REQUIRE_APPROVAL` all prevent
execution.

Protect a completed OpenAI-compatible Responses payload without adding an
OpenAI SDK dependency:

```go
adapter, err := latch.NewOpenAIToolAdapter(client, map[string]latch.OpenAIToolHandler{
    "get_weather": func(ctx context.Context, args map[string]any) (any, error) {
        return getWeather(args["city"]), nil
    },
})
outputs, err := adapter.ExecuteResponses(ctx, responseJSON)
```

The adapter validates and allows the complete batch before executing any
handler. It also supports Chat Completions through `ExecuteChatCompletion`.

Protect a local child process with structured argv:

```go
shell, err := latch.NewShellExecutor(client)
result, err := shell.Run(ctx, latch.ShellCommand{
    ExecutionID: "agent:git-status:001",
    Executable:  "git",
    Args:        []string{"status", "--short"},
})
```

Use `RunShell` only for intentional shell syntax. Both paths resolve and
fingerprint the executable, snapshot cwd and environment, fail closed on every
non-allow result, consume replay IDs before process start, and bound runtime
and output.
