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