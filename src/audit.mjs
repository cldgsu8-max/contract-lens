const METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'trace']);
const WEIGHTS = { critical: 25, high: 12, medium: 5, low: 2 };

function issue(severity, code, location, message, remediation) {
  return { severity, code, location, message, remediation };
}

function hasSuccessResponse(responses = {}) {
  return Object.keys(responses).some((status) => /^2(?:\d\d|XX)$/i.test(status));
}

function parameterList(pathItem, operation) {
  return [...(pathItem.parameters || []), ...(operation.parameters || [])];
}

export function auditOpenApi(document) {
  const findings = [];
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new TypeError('The input must be an OpenAPI JSON object.');
  }

  if (!/^3\./.test(document.openapi || '')) {
    findings.push(issue('high', 'OAS_VERSION', '$.openapi', 'Document is not declared as OpenAPI 3.x.', 'Set the openapi field to a supported 3.x version.'));
  }

  const servers = document.servers || [];
  if (!servers.length) {
    findings.push(issue('medium', 'SERVERS_MISSING', '$.servers', 'No server URL is declared.', 'Declare at least one production or sandbox server.'));
  }
  for (const [index, server] of servers.entries()) {
    if (/^http:\/\//i.test(server.url || '')) {
      findings.push(issue('high', 'INSECURE_TRANSPORT', `$.servers[${index}].url`, `Server uses cleartext HTTP: ${server.url}`, 'Use HTTPS for every non-local server.'));
    }
  }

  const paths = document.paths || {};
  if (!Object.keys(paths).length) {
    findings.push(issue('critical', 'NO_PATHS', '$.paths', 'The contract exposes no operations.', 'Add the API paths and operations that clients can call.'));
  }

  let operationCount = 0;
  for (const [route, pathItem] of Object.entries(paths)) {
    for (const [method, operation] of Object.entries(pathItem || {})) {
      if (!METHODS.has(method.toLowerCase())) continue;
      operationCount += 1;
      const location = `$.paths[${JSON.stringify(route)}].${method}`;

      if (!operation.operationId) {
        findings.push(issue('low', 'OPERATION_ID_MISSING', location, `${method.toUpperCase()} ${route} has no stable operationId.`, 'Add a unique operationId for generated clients and observability.'));
      }

      const security = operation.security ?? document.security;
      const explicitlyPublic = Array.isArray(security) && security.length === 0;
      if (security == null) {
        const severity = ['post', 'put', 'patch', 'delete'].includes(method.toLowerCase()) ? 'high' : 'medium';
        findings.push(issue(severity, 'AUTH_UNSPECIFIED', location, `${method.toUpperCase()} ${route} does not state whether authentication is required.`, 'Declare a security requirement or use security: [] to mark the operation intentionally public.'));
      } else if (!explicitlyPublic && !Object.keys(document.components?.securitySchemes || {}).length) {
        findings.push(issue('high', 'AUTH_SCHEME_MISSING', location, 'The operation requires authentication but no security scheme is defined.', 'Define the referenced scheme under components.securitySchemes.'));
      }

      const responses = operation.responses || {};
      if (!hasSuccessResponse(responses)) {
        findings.push(issue('high', 'SUCCESS_RESPONSE_MISSING', `${location}.responses`, 'No 2xx success response is documented.', 'Document every success status and response body.'));
      }
      if (!explicitlyPublic && security != null && !responses['401'] && !responses['403']) {
        findings.push(issue('medium', 'AUTH_ERRORS_MISSING', `${location}.responses`, 'Authenticated operation omits both 401 and 403 responses.', 'Document authentication and authorization failures.'));
      }

      const templateParams = [...route.matchAll(/\{([^}]+)\}/g)].map((match) => match[1]);
      const declaredParams = parameterList(pathItem, operation);
      for (const name of templateParams) {
        const declared = declaredParams.find((param) => param?.in === 'path' && param?.name === name);
        if (!declared) {
          findings.push(issue('high', 'PATH_PARAM_UNDECLARED', location, `Path parameter {${name}} is not declared.`, `Declare ${name} with in: path and required: true.`));
        } else if (declared.required !== true) {
          findings.push(issue('high', 'PATH_PARAM_OPTIONAL', location, `Path parameter {${name}} is not marked required.`, 'OpenAPI requires all path parameters to set required: true.'));
        }
      }

      if (operation.requestBody) {
        const variants = Object.values(operation.requestBody.content || {});
        if (!variants.length || variants.some((variant) => !variant?.schema)) {
          findings.push(issue('medium', 'REQUEST_SCHEMA_MISSING', `${location}.requestBody`, 'Request body has a media type without a schema.', 'Define a schema for every accepted request media type.'));
        }
      }
    }
  }

  const deduction = findings.reduce((sum, finding) => sum + WEIGHTS[finding.severity], 0);
  const score = Math.max(0, 100 - deduction);
  const counts = Object.fromEntries(Object.keys(WEIGHTS).map((severity) => [severity, findings.filter((f) => f.severity === severity).length]));
  return { score, grade: score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F', operationCount, counts, findings };
}

export function toMarkdown(report, source = 'OpenAPI document') {
  const lines = [
    '# Contract Lens Audit',
    '',
    `**Source:** ${source}`,
    `**Score:** ${report.score}/100 (${report.grade})`,
    `**Operations:** ${report.operationCount}`,
    `**Findings:** ${report.findings.length} — ${report.counts.critical} critical, ${report.counts.high} high, ${report.counts.medium} medium, ${report.counts.low} low`,
    '',
    '## Findings',
    '',
  ];
  if (!report.findings.length) lines.push('No findings.');
  for (const [index, finding] of report.findings.entries()) {
    lines.push(`### ${index + 1}. [${finding.severity.toUpperCase()}] ${finding.code}`, '', `- Location: \`${finding.location}\``, `- Risk: ${finding.message}`, `- Fix: ${finding.remediation}`, '');
  }
  lines.push('---', 'Generated by Contract Lens. Automated results should be validated by a human-quality contract review.');
  return lines.join('\n');
}
