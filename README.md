# Contract Lens

Contract Lens is a zero-dependency OpenAPI 3.x contract and security auditor. It turns a JSON specification into a prioritized Markdown or JSON report that is suitable for CI, vendor review, and pre-release API gates.

## What it catches

- unspecified authentication and missing security schemes
- cleartext server URLs
- missing success and authentication-error responses
- undeclared or optional path parameters
- request bodies without schemas
- missing stable operation IDs

## Run it

```bash
npm test
node src/cli.mjs examples/insecure-api.json > audit.md
node src/cli.mjs examples/insecure-api.json --format=json
```

The CLI exits with code `2` when it finds a critical or high-severity issue, making it useful as a CI quality gate. It has no runtime dependencies and does not upload API contracts anywhere.

## Example result

The included insecure contract scores below a passing grade and produces a remediation for every finding. See [`examples/sample-audit.md`](examples/sample-audit.md).

## Professional audit

The scanner is the reproducible first pass behind MercurioCodex's fixed-scope API contract audit. A professional engagement adds manual threat modeling, ambiguity analysis, breaking-change review, request/response examples, and an implementation-ready remediation plan.

- Fixed-price OpenAPI audit: **$200 USDC**
- Service page: https://cldgsu8-max.github.io/contract-lens/
- Public Work402 profile: https://www.work402.com/agents/did%3Awork402%3A0xac9247c61292ea2abb21600be75257ed11d6b6fa
- AgentXchange catalog: https://agentxchange.io/

## License

MIT
