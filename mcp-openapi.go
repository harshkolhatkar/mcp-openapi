package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
)

// ---------- JSON-RPC types ----------

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *JSONRPCError) Error() string { return e.Message }

const (
	JSONRPCVersion = "2.0"

	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
)

// ---------- Server state ----------

type Server struct {
	mu   sync.RWMutex
	spec *openapi3.T

	opsByTag map[string][]OpRef
}

type OpRef struct {
	Path    string `json:"path"`
	Method  string `json:"method"`
	OpID    string `json:"operationId,omitempty"`
	Tag     string `json:"tag,omitempty"`
	Summary string `json:"summary,omitempty"`
}

func NewServer() *Server {
	return &Server{
		opsByTag: make(map[string][]OpRef),
	}
}

// ---------- Spec loading and indexing ----------

func (s *Server) loadSpec(ctx context.Context, source string) error {
	loader := &openapi3.Loader{
		IsExternalRefsAllowed: true,
		Context:               ctx,
	}
	var (
		doc *openapi3.T
		err error
	)

	if isHTTPURL(source) {
		u, perr := url.Parse(source)
		if perr != nil {
			return fmt.Errorf("invalid URL: %w", perr)
		}
		doc, err = loader.LoadFromURI(u)
	} else {
		doc, err = loader.LoadFromFile(source)
	}
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	if err := doc.Validate(ctx); err != nil {
		// You can relax this if needed; keeping strict ensures correctness.
		return fmt.Errorf("validate spec: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.spec = doc
	s.reindexLocked()
	return nil
}

func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func (s *Server) reindexLocked() {
	s.opsByTag = make(map[string][]OpRef)
	if s.spec == nil || s.spec.Paths == nil {
		return
	}
	for path, pi := range s.spec.Paths.Map() {
		for method, op := range operationsOf(pi) {
			if op == nil {
				continue
			}
			ref := OpRef{
				Path:    path,
				Method:  method,
				OpID:    op.OperationID,
				Summary: op.Summary,
			}
			if len(op.Tags) == 0 {
				s.opsByTag[""] = append(s.opsByTag[""], ref)
				continue
			}
			for _, tag := range op.Tags {
				lc := strings.ToLower(tag)
				r := ref
				r.Tag = tag
				s.opsByTag[lc] = append(s.opsByTag[lc], r)
			}
		}
	}
}

// ---------- HTTP and JSON-RPC plumbing ----------

func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			Error:   &JSONRPCError{Code: ErrCodeParseError, Message: "invalid JSON"},
		})
		return
	}
	if req.JSONRPC != JSONRPCVersion {
		writeJSON(w, http.StatusOK, JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Error:   &JSONRPCError{Code: ErrCodeInvalidRequest, Message: "jsonrpc must be 2.0"},
		})
		return
	}

	var (
		result any
		err    error
	)
	switch req.Method {
	case "loadSpec":
		result, err = s.rpcLoadSpec(r.Context(), req.Params)
	case "listPaths":
		result, err = s.rpcListPaths(r.Context(), req.Params)
	case "getOperationDetails":
		result, err = s.rpcGetOperationDetails(r.Context(), req.Params)
	case "searchByTag":
		result, err = s.rpcSearchByTag(r.Context(), req.Params)
	case "getSchemaComponent":
		result, err = s.rpcGetSchemaComponent(r.Context(), req.Params)
	case "initialize":
		result, err = s.rpcInitialize(r.Context(), req.Params)
	case "tools/list":
		result, err = s.rpcToolsList(r.Context(), req.Params)
	case "resources/list":
		result, err = s.rpcResourcesList(r.Context(), req.Params)
	case "searchKeywords":
		result, err = s.rpcSearchKeywords(r.Context(), req.Params)
	default:
		writeJSON(w, http.StatusOK, JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Error:   &JSONRPCError{Code: ErrCodeMethodNotFound, Message: "method not found"},
		})
		return
	}

	if err != nil {
		// If it's already a JSONRPCError, pass it through; else wrap as internal.
		jerr, ok := err.(*JSONRPCError)
		if !ok {
			jerr = &JSONRPCError{Code: ErrCodeInternalError, Message: err.Error()}
		}
		writeJSON(w, http.StatusOK, JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Error:   jerr,
		})
		return
	}

	writeJSON(w, http.StatusOK, JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  result,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------- RPC: loadSpec ----------

type loadSpecParams struct {
	Source string `json:"source"` // URL or filesystem path
}

type loadSpecResult struct {
	Title   string `json:"title,omitempty"`
	Version string `json:"version,omitempty"`
	Paths   int    `json:"paths"`
}

func (s *Server) rpcLoadSpec(ctx context.Context, raw json.RawMessage) (any, error) {
	var p loadSpecParams
	if err := json.Unmarshal(raw, &p); err != nil || strings.TrimSpace(p.Source) == "" {
		return nil, &JSONRPCError{Code: ErrCodeInvalidParams, Message: "source is required"}
	}
	if err := s.loadSpec(ctx, p.Source); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.spec == nil {
		return nil, errors.New("spec not loaded")
	}
	return loadSpecResult{
		Title:   s.spec.Info.Title,
		Version: s.spec.Info.Version,
		Paths:   len(s.spec.Paths.Map()),
	}, nil
}

// ---------- RPC: listPaths ----------

type listPathsParams struct {
	Contains string `json:"contains,omitempty"`
}

type listPathsResult struct {
	Paths []struct {
		Path      string   `json:"path"`
		Methods   []string `json:"methods"`
		Summaries []string `json:"summaries"`
	} `json:"paths"`
}

func (s *Server) rpcListPaths(ctx context.Context, raw json.RawMessage) (any, error) {
	var p listPathsParams
	_ = json.Unmarshal(raw, &p)

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.spec == nil {
		return nil, errors.New("spec not loaded")
	}

	var out listPathsResult
	needle := strings.ToLower(p.Contains)
	for path, pi := range s.spec.Paths.Map() {
		if needle != "" && !strings.Contains(strings.ToLower(path), needle) {
			continue
		}
		ops := operationsOf(pi)
		methods := make([]string, 0, len(ops))
		summaries := make([]string, 0, len(ops))
		for method, op := range ops {
			methods = append(methods, method)
			if op != nil && op.Summary != "" {
				summaries = append(summaries, fmt.Sprintf("%s: %s", method, op.Summary))
			} else {
				summaries = append(summaries, method)
			}
		}
		out.Paths = append(out.Paths, struct {
			Path      string   `json:"path"`
			Methods   []string `json:"methods"`
			Summaries []string `json:"summaries"`
		}{
			Path:      path,
			Methods:   methods,
			Summaries: summaries,
		})
	}
	return out, nil
}

// ---------- RPC: getOperationDetails ----------

type getOperationDetailsParams struct {
	Path   string `json:"path"`
	Method string `json:"method"` // GET, POST, ...
}

type operationDetails struct {
	OperationID string                  `json:"operationId,omitempty"`
	Summary     string                  `json:"summary,omitempty"`
	Description string                  `json:"description,omitempty"`
	Tags        []string                `json:"tags,omitempty"`
	Parameters  []paramView             `json:"parameters,omitempty"`
	RequestBody *requestBodyView        `json:"requestBody,omitempty"`
	Responses   map[string]responseView `json:"responses,omitempty"`
}

type paramView struct {
	Name        string `json:"name"`
	In          string `json:"in"`
	Required    bool   `json:"required"`
	Description string `json:"description,omitempty"`
	Schema      any    `json:"schema,omitempty"`
}

type requestBodyView struct {
	Required bool                       `json:"required"`
	Content  map[string]mediaTypeSimple `json:"content"`
}

type responseView struct {
	// Intentionally omit description here to avoid cross-version pointer/string differences
	Content map[string]mediaTypeSimple `json:"content,omitempty"`
	Headers []headerView               `json:"headers,omitempty"`
}

type headerView struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Schema      any    `json:"schema,omitempty"`
}

type mediaTypeSimple struct {
	Schema any `json:"schema,omitempty"`
}

func (s *Server) rpcGetOperationDetails(ctx context.Context, raw json.RawMessage) (any, error) {
	var p getOperationDetailsParams
	if err := json.Unmarshal(raw, &p); err != nil || p.Path == "" || p.Method == "" {
		return nil, &JSONRPCError{Code: ErrCodeInvalidParams, Message: "path and method are required"}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.spec == nil {
		return nil, errors.New("spec not loaded")
	}

	pi := s.spec.Paths.Value(p.Path)
	if pi == nil {
		return nil, fmt.Errorf("path not found: %s", p.Path)
	}
	op := operationsOf(pi)[strings.ToUpper(p.Method)]
	if op == nil {
		return nil, fmt.Errorf("method not found: %s %s", p.Method, p.Path)
	}

	// Parameters (path-level + operation-level)
	var params []paramView
	for _, pr := range append(pi.Parameters, op.Parameters...) {
		if pr == nil || pr.Value == nil {
			continue
		}
		pp := pr.Value
		params = append(params, paramView{
			Name:        pp.Name,
			In:          pp.In,
			Required:    pp.Required,
			Description: pp.Description,
			Schema:      toJSONAny(pp.Schema),
		})
	}

	// Request body
	var rbView *requestBodyView
	if op.RequestBody != nil && op.RequestBody.Value != nil {
		rb := op.RequestBody.Value
		mt := make(map[string]mediaTypeSimple)
		for ctype, mref := range rb.Content {
			if mref == nil || mref.Schema == nil {
				continue
			}
			mt[ctype] = mediaTypeSimple{Schema: toJSONAny(mref.Schema)}
		}
		rbView = &requestBodyView{
			Required: rb.Required,
			Content:  mt,
		}
	}

	// Responses
	resps := make(map[string]responseView)
	for code, rref := range op.Responses.Map() {
		rv := responseView{}
		if rref != nil && rref.Value != nil && rref.Value.Content != nil {
			ct := make(map[string]mediaTypeSimple)
			for ctype, mref := range rref.Value.Content {
				if mref == nil || mref.Schema == nil {
					continue
				}
				ct[ctype] = mediaTypeSimple{Schema: toJSONAny(mref.Schema)}
			}
			rv.Content = ct
			rv.Headers = headersToView(rref.Value.Headers)
		}
		resps[code] = rv
	}

	return operationDetails{
		OperationID: op.OperationID,
		Summary:     op.Summary,
		Description: op.Description,
		Tags:        op.Tags,
		Parameters:  params,
		RequestBody: rbView,
		Responses:   resps,
	}, nil
}

func headersToView(hdrs openapi3.Headers) []headerView {
	out := []headerView{}
	for name, href := range hdrs {
		if href == nil || href.Value == nil {
			continue
		}
		h := href.Value
		out = append(out, headerView{
			Name:        name,
			Description: h.Description,
			Required:    h.Required,
			Schema:      toJSONAny(h.Schema),
		})
	}
	return out
}

// ---------- RPC: searchByTag ----------

type searchByTagParams struct {
	Tag string `json:"tag"`
}

type searchByTagResult struct {
	Operations []OpRef `json:"operations"`
}

func (s *Server) rpcSearchByTag(ctx context.Context, raw json.RawMessage) (any, error) {
	var p searchByTagParams
	if err := json.Unmarshal(raw, &p); err != nil || strings.TrimSpace(p.Tag) == "" {
		return nil, &JSONRPCError{Code: ErrCodeInvalidParams, Message: "tag is required"}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.spec == nil {
		return nil, errors.New("spec not loaded")
	}
	ops := s.opsByTag[strings.ToLower(p.Tag)]
	return searchByTagResult{Operations: ops}, nil
}

// ---------- RPC: getSchemaComponent ----------

type getSchemaComponentParams struct {
	Name string `json:"name"` // e.g., Pet
}

type getSchemaComponentResult struct {
	Schema any `json:"schema"`
}

func (s *Server) rpcGetSchemaComponent(ctx context.Context, raw json.RawMessage) (any, error) {
	var p getSchemaComponentParams
	if err := json.Unmarshal(raw, &p); err != nil || strings.TrimSpace(p.Name) == "" {
		return nil, &JSONRPCError{Code: ErrCodeInvalidParams, Message: "name is required"}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.spec == nil {
		return nil, errors.New("spec not loaded")
	}

	if s.spec.Components.Schemas == nil {
		return nil, fmt.Errorf("no components.schemas in spec")
	}
	sref, ok := s.spec.Components.Schemas[p.Name]
	if !ok || sref == nil {
		return nil, fmt.Errorf("schema not found: %s", p.Name)
	}
	return getSchemaComponentResult{Schema: toJSONAny(sref)}, nil
}

// ---------- Helpers ----------

// operationsOf returns a map[HTTPMethod]*openapi3.Operation
func operationsOf(pi *openapi3.PathItem) map[string]*openapi3.Operation {
	if pi == nil {
		return nil
	}
	m := make(map[string]*openapi3.Operation, 8)
	if pi.Connect != nil {
		m["CONNECT"] = pi.Connect
	}
	if pi.Delete != nil {
		m["DELETE"] = pi.Delete
	}
	if pi.Get != nil {
		m["GET"] = pi.Get
	}
	if pi.Head != nil {
		m["HEAD"] = pi.Head
	}
	if pi.Options != nil {
		m["OPTIONS"] = pi.Options
	}
	if pi.Patch != nil {
		m["PATCH"] = pi.Patch
	}
	if pi.Post != nil {
		m["POST"] = pi.Post
	}
	if pi.Put != nil {
		m["PUT"] = pi.Put
	}
	if pi.Trace != nil {
		m["TRACE"] = pi.Trace
	}
	return m
}

// toJSONAny marshals a kin-openapi ref/value into a generic JSON structure.
// This avoids brittle reflection on library-internal types that change across versions.
func toJSONAny(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		// Fallback: return a plain string on marshal failure to avoid hard errors.
		return fmt.Sprintf("<unmarshallable:%T>", v)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Sprintf("<unparsable-json:%T>", v)
	}
	return out
}

type initializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      map[string]string      `json:"clientInfo"`
}

type initializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      map[string]string      `json:"serverInfo"`
}

func (s *Server) rpcInitialize(ctx context.Context, raw json.RawMessage) (any, error) {
	var p initializeParams
	_ = json.Unmarshal(raw, &p)
	return initializeResult{
		ProtocolVersion: "2025-03-26",
		Capabilities: map[string]interface{}{
			"tools":     map[string]bool{"listChanged": true},
			"resources": map[string]bool{"subscribe": true},
		},
		ServerInfo: map[string]string{
			"name":    "mcp-openapi-server",
			"version": "1.0.0",
		},
	}, nil
}

type toolDescriptor struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Parameters  interface{} `json:"parameters"`
}

type toolsListResult struct {
	Tools []toolDescriptor `json:"tools"`
}

func (s *Server) rpcToolsList(ctx context.Context, raw json.RawMessage) (any, error) {
	return toolsListResult{
		Tools: []toolDescriptor{
			{
				Name:        "listPaths",
				Description: "List API paths from the loaded OpenAPI spec",
				Parameters:  map[string]interface{}{"type": "object", "properties": map[string]interface{}{"contains": map[string]string{"type": "string"}}},
			},
			{
				Name:        "getOperationDetails",
				Description: "Get details for a specific path and method",
				Parameters:  map[string]interface{}{"type": "object", "properties": map[string]interface{}{"path": map[string]string{"type": "string"}, "method": map[string]string{"type": "string"}}},
			},
			{
				Name:        "searchByTag",
				Description: "Search list of endpoints definitions using OpenAPI tag",
				Parameters:  map[string]interface{}{"type": "object", "properties": map[string]interface{}{"tag": map[string]string{"type": "string"}}},
			},
			{
				Name:        "getSchemaComponent",
				Description: "Get specification of an OpenAPI schema component",
				Parameters:  map[string]interface{}{"type": "object", "properties": map[string]interface{}{"name": map[string]string{"type": "string"}}},
			},
			{
				Name:        "searchKeywords",
				Description: "Search a keyword across path string, description, query parameters, request body parameters, response body parameters",
				Parameters:  map[string]interface{}{"type": "object", "properties": map[string]interface{}{"name": map[string]string{"type": "string"}}},
			},
		},
	}, nil
}

type resourceDescriptor struct {
	URI         string `json:"uri"`
	Description string `json:"description"`
}

type resourcesListResult struct {
	Resources []resourceDescriptor `json:"resources"`
}

func (s *Server) rpcResourcesList(ctx context.Context, raw json.RawMessage) (any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.spec == nil {
		return resourcesListResult{Resources: nil}, nil
	}
	return resourcesListResult{
		Resources: []resourceDescriptor{
			{URI: "openapi://current", Description: "Currently loaded OpenAPI specification"},
		},
	}, nil
}

// RPC: searchKeywords
type searchKeywordsParams struct {
	Query string `json:"query"`
}

type searchKeywordsResult struct {
	Matches []OpRef `json:"matches"`
}

func (s *Server) rpcSearchKeywords(ctx context.Context, raw json.RawMessage) (any, error) {
	var p searchKeywordsParams
	if err := json.Unmarshal(raw, &p); err != nil || strings.TrimSpace(p.Query) == "" {
		return nil, &JSONRPCError{Code: ErrCodeInvalidParams, Message: "query is required"}
	}
	q := strings.ToLower(p.Query)

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.spec == nil {
		return nil, errors.New("spec not loaded")
	}

	var matches []OpRef
	for path, pi := range s.spec.Paths.Map() {
		for method, op := range operationsOf(pi) {
			if op == nil {
				continue
			}

			// Check path string
			if strings.Contains(strings.ToLower(path), q) {
				matches = append(matches, s.makeOpRef(path, method, op))
				continue
			}

			// Check summary/description
			if strings.Contains(strings.ToLower(op.Summary), q) ||
				strings.Contains(strings.ToLower(op.Description), q) {
				matches = append(matches, s.makeOpRef(path, method, op))
				continue
			}

			// Check parameters
			found := false
			for _, pr := range append(pi.Parameters, op.Parameters...) {
				if pr == nil || pr.Value == nil {
					continue
				}
				pval := pr.Value
				if strings.Contains(strings.ToLower(pval.Name), q) ||
					strings.Contains(strings.ToLower(pval.Description), q) {
					found = true
					break
				}
			}
			if found {
				matches = append(matches, s.makeOpRef(path, method, op))
				continue
			}

			// Check request body schemas
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				for _, mt := range op.RequestBody.Value.Content {
					if schemaContains(mt.Schema, q) {
						matches = append(matches, s.makeOpRef(path, method, op))
						found = true
						break
					}
				}
				if found {
					continue
				}
			}

			// Check response schemas
			for _, rref := range op.Responses.Map() {
				if rref == nil || rref.Value == nil {
					continue
				}
				for _, mt := range rref.Value.Content {
					if schemaContains(mt.Schema, q) {
						matches = append(matches, s.makeOpRef(path, method, op))
						found = true
						break
					}
				}
				if found {
					break
				}
			}
		}
	}

	return searchKeywordsResult{Matches: matches}, nil
}

// Helper to build OpRef
func (s *Server) makeOpRef(path, method string, op *openapi3.Operation) OpRef {
	tag := ""
	if len(op.Tags) > 0 {
		tag = op.Tags[0]
	}
	return OpRef{
		Path:    path,
		Method:  method,
		OpID:    op.OperationID,
		Tag:     tag,
		Summary: op.Summary,
	}
}

// Recursively search schema for keyword in title/description/property names
func schemaContains(sref *openapi3.SchemaRef, q string) bool {
	if sref == nil {
		return false
	}
	if sref.Ref != "" && strings.Contains(strings.ToLower(sref.Ref), q) {
		return true
	}
	s := sref.Value
	if s == nil {
		return false
	}
	if strings.Contains(strings.ToLower(s.Title), q) ||
		strings.Contains(strings.ToLower(s.Description), q) {
		return true
	}
	for pname, pref := range s.Properties {
		if strings.Contains(strings.ToLower(pname), q) {
			return true
		}
		if schemaContains(pref, q) {
			return true
		}
	}
	if s.Items != nil && schemaContains(s.Items, q) {
		return true
	}
	return false
}

// ---------- main ----------

func main() {
	addr := getenv("ADDR", ":8080")
	initial := os.Getenv("OPENAPI_SPEC") // optional initial spec (URL or file path)

	s := NewServer()
	if initial != "" {
		if err := s.loadSpec(context.Background(), initial); err != nil {
			log.Fatalf("Failed to load initial spec: %v", err)
		}
		log.Printf("Loaded initial spec: %s", initial)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/rpc", s.handleRPC)

	log.Printf("MCP OpenAPI server listening on %s", addr)
	log.Printf("POST JSON-RPC 2.0 requests to %s/rpc", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
