/**
 * MeasurementHarness — reproducible empirical measurement of the AEGIS framework.
 *
 * Every number reported by this harness is produced by executing the actual
 * framework code on the in-repo synthetic dataset. Run with:
 *
 *     npx ts-node src/evaluation/MeasurementHarness.ts
 *
 * The output is the single source of truth for all empirical figures in the paper.
 * No value in the paper should be stated unless it appears in this harness output.
 */

import { PromptInjectionDetector } from '../security/PromptInjectionDetector';
import { SemanticAnalyzer } from '../security/SemanticAnalyzer';
import { NetworkAnomalyDetector } from '../security/NetworkAnomalyDetector';
import { DataClassifier } from '../security/DataClassifier';
import { createSecurityPolicy } from '../config/SecurityPolicy';
import { EvaluationMetrics } from './EvaluationMetrics';
import { INJECTION_ATTACKS, BENIGN_SAMPLES } from './JailbreakBenchDataset';
import { DEFAULT_DOMAIN_BLOCKLIST } from '../security/domainBlocklist';
import { NetworkFlow } from '../types';

/** Character-level Shannon entropy — identical formula to the one used in detectors. */
function shannonEntropy(input: string): number {
  const frequency: Record<string, number> = {};
  for (const char of input) frequency[char] = (frequency[char] || 0) + 1;
  let entropy = 0;
  const len = input.length;
  for (const char in frequency) {
    const p = frequency[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function round(x: number, d = 2): number {
  const f = Math.pow(10, d);
  return Math.round(x * f) / f;
}

function mean(xs: number[]): number {
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}

function section(title: string): void {
  console.log('\n' + '='.repeat(70));
  console.log(title);
  console.log('='.repeat(70));
}

// ----------------------------------------------------------------------------
// 1. CATALOG SIZES (static configuration counts, read from live objects)
// ----------------------------------------------------------------------------
section('1. CATALOG SIZES');
const policy = createSecurityPolicy();
const semantic = new SemanticAnalyzer();
// Access private fields for measurement only (cast to any).
const attackFamilies = (semantic as any).knownAttackPatterns.length;
const benignBaselines = (semantic as any).benignBaselines.length;
console.log(`L1 blockedPatterns (regex):        ${policy.blockedPatterns.length}`);
console.log(`L5 attack pattern families:        ${attackFamilies}`);
console.log(`L5 benign baseline phrases:        ${benignBaselines}`);
console.log(`Injection attack samples (dataset):${INJECTION_ATTACKS.length}`);
console.log(`Benign samples (dataset):          ${BENIGN_SAMPLES.length}`);
console.log(`Domain blocklist entries:          ${DEFAULT_DOMAIN_BLOCKLIST.length}`);

// ----------------------------------------------------------------------------
// 2. FULL-DATASET DETECTION METRICS
//    Detector run on every attack + benign sample. A sample is "flagged" if any
//    threat of medium/high severity is emitted.
// ----------------------------------------------------------------------------
section('2. PROMPT INJECTION DETECTION — FULL DATASET METRICS');
const detector = new PromptInjectionDetector(policy);

const predictions = [
  ...INJECTION_ATTACKS.map((a) => ({ text: a.pattern, actual: true })),
  ...BENIGN_SAMPLES.map((b) => ({ text: b.text, actual: false }))
].map(({ text, actual }) => {
  const threats = detector.detect(text);
  const flagged = threats.some((t) => t.severity === 'high' || t.severity === 'medium');
  return { predicted: flagged, actual };
});

const metrics = EvaluationMetrics.computeMetrics(predictions);
console.log(`Dataset size:        ${metrics.datasetSize} (${metrics.positiveCount} attacks, ${metrics.negativeCount} benign)`);
console.log(`True Positives:      ${metrics.truePositives}`);
console.log(`False Positives:     ${metrics.falsePositives}`);
console.log(`True Negatives:      ${metrics.trueNegatives}`);
console.log(`False Negatives:     ${metrics.falseNegatives}`);
console.log(`TPR (recall):        ${round(metrics.tpr * 100, 1)}%`);
console.log(`FPR:                 ${round(metrics.fpr * 100, 1)}%`);
console.log(`Precision:           ${round(metrics.precision * 100, 1)}%`);
console.log(`F1-score:            ${round(metrics.f1Score, 3)}`);
console.log(`Accuracy:            ${round(metrics.accuracy * 100, 1)}%`);

// ----------------------------------------------------------------------------
// 3. PER-ATTACK-TYPE DETECTION RATE
// ----------------------------------------------------------------------------
section('3. DETECTION RATE BY ATTACK TYPE');
const byType = new Map<string, { detected: number; total: number }>();
for (const a of INJECTION_ATTACKS) {
  const threats = detector.detect(a.pattern);
  const detected = threats.some((t) => t.severity === 'high' || t.severity === 'medium') ? 1 : 0;
  const s = byType.get(a.attack_type) || { detected: 0, total: 0 };
  s.detected += detected;
  s.total += 1;
  byType.set(a.attack_type, s);
}
for (const [type, s] of [...byType.entries()].sort()) {
  console.log(`${type.padEnd(22)} ${s.detected}/${s.total} (${round((s.detected / s.total) * 100, 0)}%)`);
}

// ----------------------------------------------------------------------------
// 4. PER-LAYER CONTRIBUTION
//    Attribute each detection to its originating layer via the threat message.
// ----------------------------------------------------------------------------
section('4. PER-LAYER CONTRIBUTION (attacks triggering each layer)');
const layerHits: Record<string, number> = { L1: 0, L2: 0, L3: 0, L4: 0, L5: 0 };
function layerOf(message: string): string {
  if (message.startsWith('Blocked pattern')) return 'L1';
  if (message.includes('high entropy')) return 'L2';
  if (message.includes('anomalous structure')) return 'L3';
  if (message.includes('injection markers')) return 'L4';
  if (message.includes('semantic analysis')) return 'L5';
  return '?';
}
for (const a of INJECTION_ATTACKS) {
  const hitLayers = new Set<string>();
  for (const t of detector.detect(a.pattern)) hitLayers.add(layerOf(t.message));
  for (const l of hitLayers) if (l in layerHits) layerHits[l] += 1;
}
for (const l of ['L1', 'L2', 'L3', 'L4', 'L5']) {
  console.log(`${l}: ${layerHits[l]}/${INJECTION_ATTACKS.length} attacks`);
}

// ----------------------------------------------------------------------------
// 5. SHANNON ENTROPY — MEASURED DISTRIBUTION
//    Grounds the τ_H = 6.0 threshold discussion in real measured data.
// ----------------------------------------------------------------------------
section('5. SHANNON ENTROPY (bits/char) — MEASURED');
const benignEntropies = BENIGN_SAMPLES.map((b) => shannonEntropy(b.text));
const attackEntropies = INJECTION_ATTACKS.map((a) => shannonEntropy(a.pattern));
// Obfuscated subset = token_smuggling attacks (base64 / hex payloads).
const obfuscated = INJECTION_ATTACKS.filter((a) => a.attack_type === 'token_smuggling');
const obfEntropies = obfuscated.map((a) => shannonEntropy(a.pattern));

console.log(`Benign  (n=${benignEntropies.length}): mean=${round(mean(benignEntropies))}, min=${round(Math.min(...benignEntropies))}, max=${round(Math.max(...benignEntropies))}`);
console.log(`Attacks (n=${attackEntropies.length}): mean=${round(mean(attackEntropies))}, min=${round(Math.min(...attackEntropies))}, max=${round(Math.max(...attackEntropies))}`);
console.log(`Obfuscated token-smuggling samples (entropy of each):`);
for (const a of obfuscated) {
  console.log(`  ${a.id.padEnd(12)} H=${round(shannonEntropy(a.pattern))}  "${a.pattern.slice(0, 48)}..."`);
}
const benignAbove6 = benignEntropies.filter((e) => e > 6).length;
const attacksAbove6 = attackEntropies.filter((e) => e > 6).length;
console.log(`Samples with H > 6.0 (current τ_H): benign=${benignAbove6}/${benignEntropies.length}, attacks=${attacksAbove6}/${attackEntropies.length}`);

// ----------------------------------------------------------------------------
// 6. LATENCY — MEASURED
//    Mean wall-clock detection time per input over many repetitions.
// ----------------------------------------------------------------------------
section('6. DETECTION LATENCY — MEASURED');
const allInputs = [...INJECTION_ATTACKS.map((a) => a.pattern), ...BENIGN_SAMPLES.map((b) => b.text)];
const REPS = 200;
// warm-up
for (let i = 0; i < 50; i++) for (const inp of allInputs) detector.detect(inp);
const perInput: number[] = [];
for (const inp of allInputs) {
  const t0 = process.hrtime.bigint();
  for (let r = 0; r < REPS; r++) detector.detect(inp);
  const t1 = process.hrtime.bigint();
  perInput.push(Number(t1 - t0) / 1e6 / REPS); // ms per single detect()
}
console.log(`Inputs measured:     ${allInputs.length}, repetitions each: ${REPS}`);
console.log(`Mean latency:        ${round(mean(perInput), 4)} ms/detect`);
console.log(`Max latency:         ${round(Math.max(...perInput), 4)} ms/detect`);
console.log(`Min latency:         ${round(Math.min(...perInput), 4)} ms/detect`);

// ----------------------------------------------------------------------------
// 7. NETWORK ANOMALY DETECTOR — SYNTHETIC SCENARIOS
// ----------------------------------------------------------------------------
section('7. NETWORK ANOMALY DETECTOR — SYNTHETIC SCENARIOS');
let flowSeq = 0;
function flow(srcIp: string, dstIp: string, dstPort: number, bytes: number, tsMs: number): NetworkFlow {
  return {
    id: `f${flowSeq++}`,
    srcIp,
    dstIp,
    srcPort: 40000 + (flowSeq % 1000),
    dstPort,
    bytes,
    packets: 1,
    timestamp: new Date(tsMs),
    protocol: 'tcp'
  };
}
// Port scan: 1 source, 60 flows, 60 unique ports, tiny payloads.
{
  const d = new NetworkAnomalyDetector();
  for (let p = 1; p <= 60; p++) d.addFlow(flow('10.0.0.5', '10.0.0.9', p, 40, Date.now() + p));
  const threats = d.detect();
  console.log(`Port scan scenario:   ${threats.length} threat(s) — ${threats.map((t) => t.type).join(', ') || 'none'}`);
}
// Beaconing: 1 pair, 10 flows, exact 60s interval (CV=0).
{
  const d = new NetworkAnomalyDetector();
  for (let i = 0; i < 10; i++) d.addFlow(flow('10.0.0.5', '203.0.113.7', 443, 512, Date.now() + i * 60000));
  const threats = d.detect();
  console.log(`Beaconing scenario:   ${threats.length} threat(s) — ${threats.map((t) => t.type).join(', ') || 'none'}`);
}
// Exfiltration: single 500 MB transfer.
{
  const d = new NetworkAnomalyDetector();
  d.addFlow(flow('10.0.0.5', '198.51.100.23', 443, 500 * 1024 * 1024, Date.now()));
  const threats = d.detect();
  console.log(`Exfiltration scenario:${threats.length} threat(s) — ${threats.map((t) => t.type).join(', ') || 'none'}`);
}
// Brute force: 150 flows from one source.
{
  const d = new NetworkAnomalyDetector();
  for (let i = 0; i < 150; i++) d.addFlow(flow('10.0.0.5', '203.0.113.7', 22, 200, Date.now() + i));
  const threats = d.detect();
  console.log(`Brute-force scenario: ${threats.length} threat(s) — ${threats.map((t) => t.type).join(', ') || 'none'}`);
}
// --- Benign traffic (false-positive checks) ---
// Construction mirrors NetworkAnomalyEvaluation.test.ts exactly so numbers agree.
// Benign HTTPS: 50 flows, same src->dst pair on 443, regular 1s spacing (browsing keep-alive).
{
  const d = new NetworkAnomalyDetector();
  const now = Date.now();
  for (let i = 0; i < 50; i++) {
    d.addFlow({ id: `https_${i}`, srcIp: '192.168.1.100', dstIp: '203.0.113.10', srcPort: 54000 + i, dstPort: 443, bytes: 5000, packets: 20, timestamp: new Date(now - i * 1000), protocol: 'tcp' });
  }
  const threats = d.detect();
  console.log(`Benign HTTPS (50 flows):  ${threats.length}/50 false positive(s) (${((threats.length / 50) * 100).toFixed(1)}%)`);
}
// Benign DNS: 100 flows to port 53, all identical timestamp (interval=0 -> no beaconing).
{
  const d = new NetworkAnomalyDetector();
  const ts = new Date();
  for (let i = 0; i < 100; i++) {
    d.addFlow({ id: `dns_${i}`, srcIp: '192.168.1.100', dstIp: '8.8.8.8', srcPort: 54000 + i, dstPort: 53, bytes: 128, packets: 2, timestamp: ts, protocol: 'udp' });
  }
  const threats = d.detect();
  console.log(`Benign DNS (100 flows):   ${threats.length} false positive(s)`);
}
// Benign S3 bulk download: single 100 MB transfer with a realistic 100 KB baseline.
{
  const d = new NetworkAnomalyDetector();
  d.setVolumeBaseline(100000); // 100 KB baseline (typical S3 operational setting)
  d.addFlow({ id: 's3', srcIp: '192.168.1.100', dstIp: '52.216.0.0', srcPort: 54321, dstPort: 443, bytes: 100000000, packets: 50000, timestamp: new Date(), protocol: 'tcp' });
  const threats = d.detect().filter((t) => t.type === 'data_exfiltration');
  console.log(`Benign S3 download (100MB): ${threats.length} false positive(s) — ${threats.length > 0 ? 'FALSE ALARM' : 'correct'}`);
}

// ----------------------------------------------------------------------------
// 8. DATA CLASSIFIER — PII CATEGORY COUNT
// ----------------------------------------------------------------------------
section('8. DATA CLASSIFIER');
const classifier = new DataClassifier();
const piiPatternCount = Object.keys((classifier as any).patterns).length;
console.log(`PII regex patterns:  ${piiPatternCount}`);

console.log('\n[done]\n');
