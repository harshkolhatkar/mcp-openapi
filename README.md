OPENAPI_SPEC=https://petstore3.swagger.io/api/v3/openapi.json go run .

curl -s localhost:8080/rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0",
  "id":2,
  "method":"listPaths",
  "params": { "contains": "pet" }
}'

curl -s localhost:8080/rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0",
  "id":3,
  "method":"getOperationDetails",
  "params": { "path": "/pet", "method": "POST" }
}'

curl -s localhost:8080/rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0",
  "id":4,
  "method":"searchByTag",
  "params": { "tag": "pet" }
}'

curl -s localhost:8080/rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0",
  "id":5,
  "method":"getSchemaComponent",
  "params": { "name": "Pet" }
}'

curl -s localhost:8080/rpc -H 'Content-Type: application/json' -d '{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "searchKeywords",   
  "params": { "query": "session" }
}'

To-Dos:
- listOperations: Return a flat list of operations with fields helpful for ranking.
    - Parameters: none or optional text filter.
    - Result fields: path, method, operationId, summary, description, security, deprecation flag.
- findByOperationId: Resolve a single operation by exact operationId.
    - Parameters: { operationId: string }
- listSchemas: Return component schema names and brief descriptions to help pick payload shapes.
    - Parameters: optional prefix filter.
- getSecuritySchemes / listServers: Advertise auth and base URLs, essential for runnable tests.
