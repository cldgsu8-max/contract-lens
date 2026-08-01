import assert from 'node:assert/strict';
import test from 'node:test';
import { auditOpenApi, toMarkdown } from '../src/audit.mjs';

test('flags insecure transport, missing auth, responses, and path parameters', () => {
  const report = auditOpenApi({
    openapi: '3.1.0',
    servers: [{url: 'http://api.example.com'}],
    paths: {'/users/{id}': {delete: {responses: {'204': {description: 'deleted'}}}}},
  });
  const codes = report.findings.map((finding) => finding.code);
  assert.deepEqual(codes, ['INSECURE_TRANSPORT', 'OPERATION_ID_MISSING', 'AUTH_UNSPECIFIED', 'PATH_PARAM_UNDECLARED']);
  assert.equal(report.operationCount, 1);
  assert.equal(report.score, 62);
});

test('returns an A for a deliberately public, well-specified operation', () => {
  const report = auditOpenApi({
    openapi: '3.1.0',
    servers: [{url: 'https://api.example.com'}],
    paths: {'/health': {get: {operationId: 'getHealth', security: [], responses: {'200': {description: 'healthy'}}}}},
  });
  assert.equal(report.grade, 'A');
  assert.equal(report.findings.length, 0);
});

test('renders a deterministic Markdown report', () => {
  const markdown = toMarkdown(auditOpenApi({openapi: '3.1.0', paths: {}}), 'fixture.json');
  assert.match(markdown, /Contract Lens Audit/);
  assert.match(markdown, /NO_PATHS/);
  assert.match(markdown, /fixture\.json/);
});
