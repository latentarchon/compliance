#!/usr/bin/env node
/**
 * validate-oscal-schema.mjs
 *
 * Validates the generated OSCAL SSP JSON against the official NIST
 * OSCAL SSP JSON Schema (v1.1.3). Downloads the schema on first run
 * and caches it locally.
 *
 * Usage:
 *   node scripts/validate-oscal-schema.mjs [--ssp oscal/ssp.json]
 *
 * Exit codes:
 *   0 = valid
 *   1 = validation errors found
 *   2 = setup/download error
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

const ROOT = join(import.meta.dirname, '..');
const SCHEMA_DIR = join(ROOT, '.cache');
const SCHEMA_PATH = join(SCHEMA_DIR, 'oscal_ssp_schema.json');
const SCHEMA_URL = 'https://github.com/usnistgov/OSCAL/releases/download/v1.1.3/oscal_ssp_schema.json';
const DEFAULT_SSP = join(ROOT, 'oscal', 'ssp.json');

// Parse CLI args
const args = process.argv.slice(2);
let sspPath = DEFAULT_SSP;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--ssp' && args[i + 1]) sspPath = args[++i];
}

async function downloadSchema() {
  console.log(`Downloading OSCAL SSP schema from ${SCHEMA_URL}...`);
  const resp = await fetch(SCHEMA_URL);
  if (!resp.ok) {
    console.error(`Failed to download schema: ${resp.status} ${resp.statusText}`);
    process.exit(2);
  }
  const body = await resp.text();
  mkdirSync(SCHEMA_DIR, { recursive: true });
  writeFileSync(SCHEMA_PATH, body);
  console.log(`  Cached at ${SCHEMA_PATH}`);
  return body;
}

async function main() {
  // Load or download schema
  let schemaText;
  if (existsSync(SCHEMA_PATH)) {
    schemaText = readFileSync(SCHEMA_PATH, 'utf-8');
    console.log(`Using cached schema: ${SCHEMA_PATH}`);
  } else {
    schemaText = await downloadSchema();
  }

  const schema = JSON.parse(schemaText);

  // Load SSP
  if (!existsSync(sspPath)) {
    console.error(`SSP not found: ${sspPath}`);
    console.error('Run "npm run generate:oscal" first.');
    process.exit(2);
  }
  const ssp = JSON.parse(readFileSync(sspPath, 'utf-8'));
  console.log(`Validating: ${sspPath}`);

  // Validate
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);

  const validate = ajv.compile(schema);
  const valid = validate(ssp);

  if (valid) {
    console.log('\n✅ OSCAL SSP validates against oscal_ssp_schema.json (v1.1.3)');
    process.exit(0);
  } else {
    console.log('\n❌ OSCAL SSP validation FAILED:\n');
    const seen = new Set();
    let shown = 0;
    for (const e of validate.errors) {
      const key = e.instancePath + '|' + e.message;
      if (seen.has(key)) continue;
      seen.add(key);
      if (shown < 50) console.log(`  ${e.instancePath} — ${e.message}`);
      shown++;
    }
    if (shown > 50) console.log(`  ... and ${shown - 50} more unique errors`);
    console.log(`\nTotal: ${validate.errors.length} errors (${shown} unique)`);
    process.exit(1);
  }
}

main();
