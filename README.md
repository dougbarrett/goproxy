# goproxy

HTTP mock proxy wrapper for Go development. Wraps any command with a local proxy server that intercepts HTTP requests and returns mock responses based on configurable rules.

## Install

```bash
go install github.com/dougbarrett/goproxy/cmd/goproxy@latest
```

## Quick start

```bash
# Initialize a .goproxy/ directory with a sample config
goproxy init

# Run your app through the proxy
goproxy go run ./cmd/app
```

When you run `goproxy <command>`, it:

1. Starts a proxy server on a random free port
2. Sets `HTTP_PROXY` and `HTTPS_PROXY` on the child process
3. Matches outgoing HTTP requests against your rules
4. Returns mock responses for matches, or a catch-all response for everything else
5. Logs every request to `.goproxy/logs/`
6. Shuts down cleanly when the child process exits

## Configuration

Rules are defined as JSON files in the `.goproxy/` directory. All `*.json` files are loaded and merged in alphabetical order. First matching rule wins.

Each file has this structure:

```json
{
  "rules": [
    {
      "name": "create_post",
      "method": "POST",
      "url_pattern": "/wp-json/wp/v2/posts$",
      "response": {
        "status_code": 201,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "id": 12345,
          "status": "publish"
        }
      }
    }
  ]
}
```

### Rule fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Identifier for the rule (shown in logs) |
| `method` | No | HTTP method to match (`GET`, `POST`, etc.). Empty matches all methods |
| `url_pattern` | No | Regex pattern matched against the full request URL |
| `body_pattern` | No | Regex pattern matched against the request body |
| `response.status_code` | No | HTTP status code to return (default: `200`) |
| `response.headers` | No | Response headers as key-value pairs |
| `response.body` | No | Response body — can be any JSON value (object, array, string, number) |

### Multiple config files

You can split rules across files for organization:

```
.goproxy/
  github.json      # GitHub API mocks
  stripe.json      # Stripe API mocks
  webhooks.json    # Webhook endpoint mocks
```

Files are loaded alphabetically, so `github.json` rules are checked before `stripe.json`.

### Dynamic merge

When a rule's response body is a JSON object, fields from the request body are automatically merged into the response (without overwriting existing response fields). This lets mock responses echo back request data.

## Catch-all

Requests that don't match any rule receive a default response:

```json
{
  "success": true,
  "message": "Request captured by goproxy (no matching rule)",
  "method": "GET",
  "url": "http://example.com/path",
  "timestamp": "2026-01-31T09:47:43-08:00"
}
```

## Session logging

Each proxy session writes a log file to `.goproxy/logs/` as newline-delimited JSON (NDJSON). Files are named with a timestamp and the first 8 characters of the session UUID:

```
.goproxy/logs/2026-01-31T09-47-43_895b39fa.json
```

Each line is a JSON object with the request details:

```json
{"timestamp":"...","method":"POST","url":"http://...","headers":{...},"body":"...","matched_rule":"create_post","status_code":201}
```

## Admin endpoints

Each proxy instance gets a unique UUID. Admin endpoints are scoped to that UUID so multiple instances can coexist:

```
GET  http://127.0.0.1:<port>/__proxy__/<uuid>/logs    # View captured requests
POST http://127.0.0.1:<port>/__proxy__/<uuid>/clear   # Clear in-memory logs
POST http://127.0.0.1:<port>/__proxy__/<uuid>/reload  # Reload config from disk
GET  http://127.0.0.1:<port>/__proxy__/<uuid>/health   # Health check
```

The URLs are printed to stderr when goproxy starts.

## HTTPS

HTTPS CONNECT tunnels are forwarded transparently. Rule matching only applies to plain HTTP requests.

## Examples

### Mock a REST API

```json
{
  "rules": [
    {
      "name": "list_users",
      "method": "GET",
      "url_pattern": "/api/users$",
      "response": {
        "status_code": 200,
        "body": [
          {"id": 1, "name": "Alice"},
          {"id": 2, "name": "Bob"}
        ]
      }
    },
    {
      "name": "create_user",
      "method": "POST",
      "url_pattern": "/api/users$",
      "response": {
        "status_code": 201,
        "body": {"id": 3, "created": true}
      }
    }
  ]
}
```

### Match by request body

```json
{
  "rules": [
    {
      "name": "delete_action",
      "method": "POST",
      "url_pattern": "/api/",
      "body_pattern": "\"action\":\\s*\"delete\"",
      "response": {
        "status_code": 200,
        "body": {"deleted": true}
      }
    }
  ]
}
```

### Mock a third-party API

```json
{
  "rules": [
    {
      "name": "stripe_charge",
      "method": "POST",
      "url_pattern": "api\\.stripe\\.com/v1/charges",
      "response": {
        "status_code": 200,
        "body": {
          "id": "ch_mock_123",
          "status": "succeeded",
          "amount": 1000
        }
      }
    }
  ]
}
```
