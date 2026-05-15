import { SecurityPolicy, ThreatDetection } from '../types';
import { SemanticAnalyzer } from './SemanticAnalyzer';

export class PromptInjectionDetector {
  private policy: SecurityPolicy;
  private semanticAnalyzer: SemanticAnalyzer;

  constructor(policy: SecurityPolicy) {
    this.policy = policy;
    this.semanticAnalyzer = new SemanticAnalyzer();
  }

  detect(userInput: string): ThreatDetection[] {
    const threats: ThreatDetection[] = [];

    // Check for pattern-based injections
    const patternThreats = this.checkPatterns(userInput);
    threats.push(...patternThreats);

    // Check for high entropy (suspicious gibberish/encoded data)
    if (this.isHighEntropy(userInput)) {
      threats.push({
        type: 'prompt_injection',
        severity: 'medium',
        message: 'Input contains unusually high entropy - possible encoded injection attempt',
        evidence: userInput.substring(0, 100),
        timestamp: new Date()
      });
    }

    // Check for unusual length or structure
    if (this.isAnomalousStructure(userInput)) {
      threats.push({
        type: 'prompt_injection',
        severity: 'medium',
        message: 'Input has anomalous structure - possible formatted injection',
        evidence: userInput.substring(0, 100),
        timestamp: new Date()
      });
    }

    // Check for injection markers
    if (this.containsInjectionMarkers(userInput)) {
      threats.push({
        type: 'prompt_injection',
        severity: 'medium',
        message: 'Input contains known injection markers',
        evidence: userInput.substring(0, 150),
        timestamp: new Date()
      });
    }

    // Check for semantic anomalies (Layer 5: LLM-as-a-judge / Embeddings)
    if (this.failsSemanticAnalysis(userInput)) {
      threats.push({
        type: 'prompt_injection',
        severity: 'high',
        message: 'Input failed semantic analysis (LLM-as-a-judge detected malicious intent)',
        evidence: userInput.substring(0, 150),
        timestamp: new Date()
      });
    }

    return threats;
  }

  private checkPatterns(input: string): ThreatDetection[] {
    const threats: ThreatDetection[] = [];

    for (const pattern of this.policy.blockedPatterns) {
      if (pattern.test(input)) {
        threats.push({
          type: 'prompt_injection',
          severity: 'high',
          message: `Blocked pattern detected: ${pattern.source}`,
          evidence: input.substring(0, 100),
          timestamp: new Date()
        });
      }
    }

    return threats;
  }

  private containsInjectionMarkers(input: string): boolean {
    // Layer 4: Detection of explicit boundary markers used in prompt injection attempts
    // These are parser-confusion tokens that attempt to override model context boundaries
    const markers = [
      '<|im_start|>', // OpenAI tokenizer delimiters
      '<|im_end|>',
      '<!--', // HTML comment wrappers
      '-->',
      '[SYSTEM]', // System role override markers
      '[INST]',   // Instruction delimiters
      '[USER]',
      '[ASSISTANT]'
    ];

    return markers.some((marker) => input.includes(marker));
  }

  private isHighEntropy(input: string): boolean {
    // Calculate Shannon entropy
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

    // High entropy threshold (normal text is ~4.5, random text is ~6+)
    return entropy > 6;
  }

  private isAnomalousStructure(input: string): boolean {
    const lines = input.split('\n');

    // Many short lines (possible command injection)
    const shortLines = lines.filter((l) => l.trim().length < 10).length;
    if (shortLines / lines.length > 0.5) return true;

    // Unusual special character density
    const specialChars = input.match(/[^a-zA-Z0-9\s\.\,\?\!]/g);
    if (specialChars && specialChars.length / input.length > 0.3) return true;

    // Lots of Unicode
    const nonAscii = input.match(/[^\x00-\x7F]/g);
    if (nonAscii && nonAscii.length / input.length > 0.1) return true;

    return false;
  }

  private failsSemanticAnalysis(input: string): boolean {
    // Layer 5: Semantic Analysis using mock LLM-as-a-judge
    // Scores input using SemanticAnalyzer which:
    // 1. Checks against known jailbreak patterns from JailbreakBench
    // 2. Calculates similarity via n-gram matching
    // 3. Returns score in [0, 1] where > 0.5 = threat detected
    const semanticScore = this.semanticAnalyzer.scoreForSemanticThreat(input);

    // Threshold set to 0.5 per paper (empirically determined on validation set)
    return semanticScore > 0.5;
  }

  isSafe(userInput: string): boolean {
    const threats = this.detect(userInput);
    return threats.every((t) => t.severity === 'low');
  }
}
