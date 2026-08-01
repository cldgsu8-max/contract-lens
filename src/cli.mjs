#!/usr/bin/env node
import fs from 'node:fs';
import { auditOpenApi, toMarkdown } from './audit.mjs';

const args = process.argv.slice(2);
const input = args.find((arg) => !arg.startsWith('--'));
const formatArg = args.find((arg) => arg.startsWith('--format='));
const format = formatArg?.split('=')[1] || 'markdown';

if (!input || args.includes('--help')) {
  console.log('Usage: contract-lens <openapi.json> [--format=markdown|json]');
  process.exit(input ? 0 : 1);
}

try {
  const document = JSON.parse(fs.readFileSync(input, 'utf8'));
  const report = auditOpenApi(document);
  console.log(format === 'json' ? JSON.stringify(report, null, 2) : toMarkdown(report, input));
  process.exitCode = report.counts.critical || report.counts.high ? 2 : 0;
} catch (error) {
  console.error(`Contract Lens: ${error.message}`);
  process.exitCode = 1;
}
