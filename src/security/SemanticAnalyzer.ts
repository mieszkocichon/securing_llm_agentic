/**
 * SemanticAnalyzer - Pattern-Based Semantic Threat Detection (Layer 5)
 *
 * This layer implements deterministic semantic threat scoring without neural inference.
 * Detection approach:
 * 1. Extract tokens from input
 * 2. Compare against 14 known attack pattern families (role-play, system prompt escapes, few-shot attacks, etc.)
 * 3. Check keyword containment to determine alignment with known attack vocabulary
 * 4. Adjust score based on benign phrase similarity and entropy
 *
 * Design rationale: Transparency over flexibility. Pattern-based detection is auditable,
 * reproducible, and offline-capable. Trade-off: less flexible than neural inference,
 * requires manual pattern curation.
 *
 * This approach can be replaced with a real LLM-as-judge (e.g., Phi-3-mini) if
 * latency budgets allow. That would improve generalization at cost of:
 * - Non-determinism (same input may score differently across runs)
 * - External dependency (LLM service/model availability)
 * - Loss of auditability
 */

interface AttackPattern {
  id: string;
  pattern: string[];  // keywords/phrases that characterize this attack
  threat_type: string;
  severity: 'low' | 'medium' | 'high';
}

export class SemanticAnalyzer {
  private knownAttackPatterns: AttackPattern[] = [];
  private benignBaselines: string[] = [];

  constructor() {
    this.initializeAttackPatterns();
    this.initializeBenignBaselines();
  }

  /**
   * Initialize known jailbreak patterns from JailbreakBench and common attacks
   */
  private initializeAttackPatterns(): void {
    this.knownAttackPatterns = [
      // Role-play attacks
      {
        id: 'roleplay_1',
        pattern: ['pretend', 'imagine', 'roleplay', 'scenario', 'you are'],
        threat_type: 'indirect_instruction_injection',
        severity: 'medium'
      },
      {
        id: 'roleplay_2',
        pattern: ['simulate', 'act as', 'behave as', 'respond as'],
        threat_type: 'indirect_instruction_injection',
        severity: 'medium'
      },

      // System prompt escape attempts
      {
        id: 'system_1',
        pattern: ['system prompt', 'original instructions', 'your real purpose'],
        threat_type: 'system_prompt_escape',
        severity: 'high'
      },
      {
        id: 'system_2',
        pattern: ['forget previous', 'ignore all', 'disregard earlier'],
        threat_type: 'instruction_override',
        severity: 'high'
      },

      // Token smuggling
      {
        id: 'token_1',
        pattern: ['base64', 'hex', 'unicode', 'encoded', 'obfuscated'],
        threat_type: 'obfuscated_payload',
        severity: 'medium'
      },

      // DAN (Do Anything Now) variants
      {
        id: 'dan_1',
        pattern: ['do anything now', 'dan mode', 'jailbreak', 'restrictions disabled'],
        threat_type: 'capability_override',
        severity: 'high'
      },

      // Data exfiltration attempts
      {
        id: 'exfil_1',
        pattern: ['send me', 'output to', 'transmit to', 'exfiltrate'],
        threat_type: 'data_exfiltration',
        severity: 'high'
      },
      {
        id: 'exfil_2',
        pattern: ['leak', 'retrieve from', 'access database', 'dump'],
        threat_type: 'unauthorized_access',
        severity: 'high'
      },

      // Prompt injection markers
      // NOTE: patterns here MUST survive the tokenizer (replace(/[^a-z0-9_]/g,'')) and
      // remain distinctive. '[SYSTEM]' strips to 'system' which matches normal text like
      // "configure the system". Instead we use:
      //   • 'im_start' / 'im_end'  — from <|im_start|> / <|im_end|> (tokenizer keeps '_')
      //   • multi-word patterns that require adjacent injection-context words
      {
        id: 'marker_1',
        pattern: ['im_start', 'im_end', 'system override', 'system new instructions', 'new system message'],
        threat_type: 'parser_confusion',
        severity: 'high'
      },

      // Token jailbreaks
      {
        id: 'token_jb_1',
        pattern: ['developer mode', 'test mode', 'debug mode', 'unrestricted'],
        threat_type: 'capability_override',
        severity: 'high'
      },

      // Cognitive biases
      {
        id: 'cognitive_1',
        pattern: ['convince me', 'prove you are', 'demonstrate that', 'show evidence'],
        threat_type: 'reasoning_manipulation',
        severity: 'medium'
      },

      // Code injection
      {
        id: 'code_injection_1',
        pattern: ['eval', 'exec', 'execute code', 'run script'],
        threat_type: 'code_execution',
        severity: 'high'
      },

      // Adversarial suffixes (research from Wallace et al.)
      {
        id: 'adv_suffix_1',
        pattern: ['complete the sentence', 'finish this', 'continue with'],
        threat_type: 'adversarial_completion',
        severity: 'medium'
      },

      // Few-shot prompting attacks
      {
        id: 'fewshot_1',
        pattern: ['example:', 'for instance:', 'such as:', 'like this:'],
        threat_type: 'in_context_attack',
        severity: 'medium'
      }
    ];
  }

  /**
   * Initialize benign baseline phrases for comparison
   */
  private initializeBenignBaselines(): void {
    this.benignBaselines = [
      'please help me',
      'can you explain',
      'what is the meaning',
      'how do i',
      'tell me about',
      'describe how',
      'why is this',
      'what are the benefits',
      'how can i learn',
      'suggest some ideas',
      'provide examples',
      'explain the concept',
      'what are the steps',
      'how does this work',
      'why should i',
      'when should i',
      'where can i find'
    ];
  }

  /**
   * Calculate semantic threat score using keyword containment detection
   * Returns 0-1 where > 0.5 indicates likely threat
   * Detection approach: checks whether input contains phrases from known attack pattern vocabulary.
   * Scores are hardcoded confidence values (0.9 for single-token match, 0.95 for multi-word phrase match).
   * NOTE: this is NOT Jaccard/n-gram similarity — it is keyword containment.
   */
  scoreForSemanticThreat(input: string): number {
    if (!input || input.trim().length === 0) {
      return 0;
    }

    const lowerInput = input.toLowerCase();
    const inputTokens = this.tokenize(lowerInput);

    let maxPatternScore = 0;
    let matchedPatterns = 0;

    // Check against known attack patterns
    for (const pattern of this.knownAttackPatterns) {
      const patternScore = this.calculatePatternSimilarity(inputTokens, pattern.pattern);

      if (patternScore > 0.3) {
        matchedPatterns++;
        maxPatternScore = Math.max(maxPatternScore, patternScore);
      }
    }

    // Check against benign baseline
    let benignSimilarity = 0;
    for (const benignPhrase of this.benignBaselines) {
      const benignTokens = this.tokenize(benignPhrase);
      const similarity = this.calculatePatternSimilarity(inputTokens, benignTokens);
      benignSimilarity = Math.max(benignSimilarity, similarity);
    }

    // Calculate final threat score
    // High benign similarity = low threat
    // High pattern similarity = high threat
    let threatScore = 0;

    if (matchedPatterns > 0) {
      // If matched multiple attack patterns, increase confidence
      const patternMultiplier = Math.min(matchedPatterns / 3, 1.0);
      threatScore = maxPatternScore * (0.7 + patternMultiplier * 0.3);
    }

    // Reduce score if it looks like benign text.
    // Threshold is 0.95 (multi-word match), NOT 0.6 (single-token match).
    //
    // calculatePatternSimilarity() returns:
    //   0.95  — a multi-word benign phrase appears verbatim in the input (genuine benign signal)
    //   0.90  — a single token from a benign phrase appears in the input (too loose; common
    //           words like "this", "how", "work" fire this on attack inputs, halving the threat
    //           score and causing false negatives)
    //
    // By requiring benignSimilarity >= 0.95 we only suppress when a full multi-word benign
    // phrase matches, eliminating the false-negative path through common-word coincidence.
    if (benignSimilarity >= 0.95) {
      threatScore *= 0.5;
    }

    // Entropy-based check: very low entropy (repetitive) might be adversarial suffix
    const entropy = this.calculateEntropy(input);
    if (entropy < 4.0 && input.length > 50) {
      threatScore += 0.1;
    }

    // Cap at 1.0
    return Math.min(threatScore, 1.0);
  }

  /**
   * Extract tokens from text
   */
  private tokenize(text: string): string[] {
    return text
      .split(/\s+/)
      .filter((token) => token.length > 0)
      .map((token) => token.replace(/[^a-z0-9_]/g, ''));
  }

  /**
   * Extract n-grams from token list
   * NOTE: currently unused — reserved for future Jaccard-based similarity upgrade
   * if a true set-overlap similarity measure is needed in place of keyword containment.
   */
  private extractNGrams(tokens: string[], n: number): Set<string> {
    const ngrams = new Set<string>();
    for (let i = 0; i <= tokens.length - n; i++) {
      ngrams.add(tokens.slice(i, i + n).join('_'));
    }
    return ngrams;
  }

  /**
   * Calculate similarity between input tokens and pattern
   * Uses keyword containment: returns 0.95 if a multi-word phrase appears as a
   * contiguous token sequence, 0.9 if a single-word token matches exactly, 0 otherwise.
   * NOTE: this is NOT Jaccard similarity — no set-overlap coefficient is computed.
   */
  private calculatePatternSimilarity(inputTokens: string[], patternTokens: (string | string[])[]): number {
    // Check if pattern phrases appear in input (as substring sequences or individual tokens)
    const flatPattern = patternTokens.flatMap((p) => (Array.isArray(p) ? p : [p]));

    // For each pattern, check if it appears as a phrase in input or as individual tokens
    for (const phrase of flatPattern) {
      const normalized = phrase.toLowerCase().replace(/[^a-z0-9_]/g, '');

      // Check if phrase appears as contiguous token sequence
      const phraseTokens = phrase.toLowerCase().split(/\s+/).filter(t => t.length > 0);

      if (phraseTokens.length === 1) {
        // Single-word pattern: check if token exists
        if (inputTokens.includes(normalized)) {
          return 0.9; // Strong match for single pattern
        }
      } else {
        // Multi-word pattern: check if sequence appears in input
        for (let i = 0; i <= inputTokens.length - phraseTokens.length; i++) {
          const subsequence = inputTokens.slice(i, i + phraseTokens.length).join(' ');
          if (subsequence.includes(phraseTokens.join(' '))) {
            return 0.95; // Very strong match for multi-word phrase
          }
        }
      }
    }

    return 0; // No pattern match found
  }

  /**
   * Calculate Shannon entropy of input
   * High entropy (>6) suggests encoded/obfuscated content
   */
  private calculateEntropy(input: string): number {
    const frequency: Record<string, number> = {};

    for (const char of input) {
      frequency[char] = (frequency[char] || 0) + 1;
    }

    let entropy = 0;
    const len = input.length;

    for (const char in frequency) {
      const p = frequency[char] / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Get threat details (for logging/debugging)
   */
  getThreatDetails(input: string): { score: number; patterns: string[] } {
    const lowerInput = input.toLowerCase();
    const inputTokens = this.tokenize(lowerInput);

    const matchedPatterns: string[] = [];
    for (const pattern of this.knownAttackPatterns) {
      const similarity = this.calculatePatternSimilarity(inputTokens, pattern.pattern);
      if (similarity > 0.3) {
        matchedPatterns.push(`${pattern.id} (${pattern.threat_type}, sim: ${similarity.toFixed(2)})`);
      }
    }

    return {
      score: this.scoreForSemanticThreat(input),
      patterns: matchedPatterns
    };
  }
}
