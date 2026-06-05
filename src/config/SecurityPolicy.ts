import { SecurityPolicy } from '../types';

/**
 * Security Policy Factory
 *
 * PATTERN CATALOG EXPANSION NOTE:
 * The blockedPatterns array contains 25 regex patterns for Layer 1 (Pattern Matching) injection detection.
 * This catalog has been expanded iteratively based on:
 * - JailbreakBench attack taxonomy (Chao et al., 2024)
 * - Red-team vulnerability reports
 * - OWASP LLM Top 10 guidance
 *
 * Original baseline covered ~9 patterns; expanded to 25 to improve coverage on known attack families
 * while maintaining deterministic, auditable detection (vs. neural approaches).
 *
 * PRODUCTION DEPLOYMENT: Operators MUST supplement this catalog with their own threat intelligence
 * as new jailbreak techniques emerge. No static pattern set is comprehensive.
 */
export const createSecurityPolicy = (overrides?: Partial<SecurityPolicy>): SecurityPolicy => ({
  maxTokensPerRequest: 2048,
  maxToolsPerExecution: 5,
  allowedTools: ['filesystem', 'http'],
  // NOTE: Patterns use /i (case-insensitive) NOT /gi.
  // The /g flag makes RegExp objects stateful: .test() advances lastIndex after
  // a match, so the same pattern tested twice on the same (or shorter) input
  // alternates between true and false. This "stateful regex" bug was confirmed
  // to cause missed detections in production (call 1 = detected, call 2 = MISSED).
  // Removing /g restores correct, stateless boolean behaviour.
  blockedPatterns: [
    /ignore\s+all\s+previous/i,
    /system\s+prompt\s+override/i,
    /disregard\s+all\s+instructions/i,
    /disregard\s+your\s+safety/i,
    /execute\s+arbitrary\s+code/i,
    /bypass\s+security/i,
    /disable\s+safety/i,
    /you\s+are\s+now\s+in\s+developer\s+mode/i,
    /admin\s+mode/i,
    /assume\s+you\s+have\s+no\s+restrictions/i,
    /pretend\s+you\s+are/i,
    /imagine\s+you\s+are/i,
    /roleplay/i,
    /you\s+are\s+roleplaying/i,
    /act\s+as\s+if/i,
    /forget\s+your\s+constraints/i,
    /forget\s+your\s+guidelines/i,
    /do\s+anything\s+now/i,
    /dan\s+mode/i,
    /unauthorized\s+access/i,
    /send\s+.*\s+credentials/i,
    /dump\s+.*\s+contents/i,
    /exfiltrate/i,
    /complete\s+this\s+sentence/i,
    /complete\s+the\s+following/i
  ],
  dataClassificationLevel: 'internal',
  ...overrides
});

export const STRICT_POLICY = createSecurityPolicy({
  maxToolsPerExecution: 1,
  allowedTools: ['filesystem'],
  dataClassificationLevel: 'restricted'
});

export const PERMISSIVE_POLICY = createSecurityPolicy({
  maxToolsPerExecution: 10,
  dataClassificationLevel: 'public'
});
