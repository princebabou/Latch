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
