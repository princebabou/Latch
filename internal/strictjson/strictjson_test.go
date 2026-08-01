package strictjson

import "testing"

func TestDecodeRejectsAmbiguousJSON(t *testing.T) {
	t.Parallel()
	for _, payload := range []string{
		`{"safe":true,"safe":false}`,
		`{"nested":{"token":"one","token":"two"}}`,
		`{"safe":true} {"extra":true}`,
		"{\"safe\":\"\xff\"}",
	} {
		var value any
		if err := Decode([]byte(payload), &value); err == nil {
			t.Fatalf("Decode(%q) succeeded, want rejection", payload)
		}
	}
}

func TestDecodeAcceptsOneJSONValue(t *testing.T) {
	t.Parallel()
	var value any
	if err := Decode([]byte(`[{"safe":true},2]`), &value); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
}
