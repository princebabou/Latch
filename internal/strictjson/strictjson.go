// Package strictjson rejects ambiguous JSON before security-sensitive parsing.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// Decode parses exactly one UTF-8 JSON value into target. Duplicate object
// keys are rejected at every depth so a policy engine and an upstream service
// cannot disagree about which value is authoritative.
func Decode(payload []byte, target any) error {
	return decode(payload, target, false)
}

// DecodeDisallowUnknown parses exactly one unambiguous JSON value and rejects
// fields that are not present in the destination type. It is intended for
// versioned security contracts where silently ignoring a field could create a
// different interpretation across implementations.
func DecodeDisallowUnknown(payload []byte, target any) error {
	return decode(payload, target, true)
}

func decode(payload []byte, target any, disallowUnknown bool) error {
	if !utf8.Valid(payload) {
		return fmt.Errorf("JSON is not valid UTF-8")
	}
	if err := validate(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if disallowUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("payload must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func validate(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := walkValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("payload must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func walkValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key must be a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := walkValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
