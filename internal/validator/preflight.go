package validator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type containerFrame struct {
	isObject  bool
	expectKey bool
	keys      map[string]bool
	count     int
}

// ValidateJSONPreflight performs a single-pass O(N) token scan over raw JSON bytes,
// enforcing MaxNestingDepth (64), MaxObjectFields (1000), MaxPreflightValues (500000),
// and strictly rejecting duplicate object keys at any nesting level (preventing parser-differential smuggling).
func ValidateJSONPreflight(raw []byte) error {
	if len(raw) > MaxInputBytes {
		return fmt.Errorf("$: input exceeds %d byte limit", MaxInputBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var stack []containerFrame
	totalValues := 0
	rootSeen := false

	recordValue := func() error {
		totalValues++
		if totalValues > MaxPreflightValues {
			return fmt.Errorf("$: JSON exceeds %d total value limit", MaxPreflightValues)
		}
		if len(stack) == 0 {
			if rootSeen {
				return fmt.Errorf("$: trailing JSON data after root value")
			}
			rootSeen = true
			return nil
		}
		top := &stack[len(stack)-1]
		if top.isObject {
			top.expectKey = true
		} else {
			top.count++
		}
		return nil
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("$: invalid JSON syntax: %v", err)
		}

		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				if len(stack) > 0 {
					top := &stack[len(stack)-1]
					if top.isObject && top.expectKey {
						return fmt.Errorf("$: unexpected '{' where object key was expected")
					}
				}
				if err := recordValue(); err != nil {
					return err
				}
				if len(stack)+1 > MaxNestingDepth {
					return fmt.Errorf("$: JSON nesting depth exceeds %d", MaxNestingDepth)
				}
				stack = append(stack, containerFrame{
					isObject:  true,
					expectKey: true,
					keys:      make(map[string]bool),
				})
			case '[':
				if len(stack) > 0 {
					top := &stack[len(stack)-1]
					if top.isObject && top.expectKey {
						return fmt.Errorf("$: unexpected '[' where object key was expected")
					}
				}
				if err := recordValue(); err != nil {
					return err
				}
				if len(stack)+1 > MaxNestingDepth {
					return fmt.Errorf("$: JSON nesting depth exceeds %d", MaxNestingDepth)
				}
				stack = append(stack, containerFrame{
					isObject: false,
				})
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("$: unexpected closing delimiter %q", v)
				}
				stack = stack[:len(stack)-1]
			}
		case string:
			if len(stack) > 0 {
				top := &stack[len(stack)-1]
				if top.isObject && top.expectKey {
					if top.keys[v] {
						return fmt.Errorf("$: duplicate JSON object key %q", v)
					}
					top.keys[v] = true
					top.count++
					if top.count > MaxObjectFields {
						return fmt.Errorf("$: JSON object exceeds %d field limit", MaxObjectFields)
					}
					top.expectKey = false
					continue
				}
			}
			if err := recordValue(); err != nil {
				return err
			}
		default:
			if len(stack) > 0 {
				top := &stack[len(stack)-1]
				if top.isObject && top.expectKey {
					return fmt.Errorf("$: expected string key in JSON object")
				}
			}
			if err := recordValue(); err != nil {
				return err
			}
		}
	}

	if !rootSeen {
		return fmt.Errorf("$: empty JSON input")
	}
	if len(stack) != 0 {
		return fmt.Errorf("$: unclosed JSON container")
	}
	return nil
}
