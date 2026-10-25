package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/fabriziosalmi/security-audit-cli/internal/registry"
	"github.com/fabriziosalmi/security-audit-cli/internal/validator"
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ToolDefs returns the 12 MCP tool definitions with strict 1:1 parity to the CLI subcommands.
func ToolDefs() []map[string]any {
	return registry.ToolDefs()
}

// DispatchTool executes one of the 12 deterministic operations by MCP tool name.
func DispatchTool(name string, rawArgs json.RawMessage) (any, error) {
	return registry.DispatchTool(name, rawArgs)
}

// ServeStdio runs the JSON-RPC 2.0 MCP server over r and w.
func ServeStdio(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), validator.MaxInputBytes)
	enc := json.NewEncoder(w)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(jsonRPCResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: -32700, Message: "Parse error"},
			})
			continue
		}
		// Notifications have nil ID
		if req.ID == nil {
			continue
		}
		resp := handleRequest(req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func handleRequest(req jsonRPCRequest) jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    "sec-audit",
					"version": "0.1.2",
				},
			},
		}
	case "tools/list":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": ToolDefs(),
			},
		}
	case "tools/call":
		var params toolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32602, Message: fmt.Sprintf("invalid params: %v", err)},
			}
		}
		out, err := DispatchTool(params.Name, params.Arguments)
		if err != nil {
			errJSON, _ := json.MarshalIndent(map[string]any{"error": err.Error()}, "", "  ")
			return jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]any{
					"isError": true,
					"content": []map[string]any{
						{"type": "text", "text": string(errJSON)},
					},
				},
			}
		}
		outJSON, _ := json.MarshalIndent(out, "", "  ")
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"isError": false,
				"content": []map[string]any{
					{"type": "text", "text": string(outJSON)},
				},
			},
		}
	default:
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)},
		}
	}
}
