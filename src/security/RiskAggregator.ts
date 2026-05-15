/**
 * RiskAggregator - Multi-layer Bayesian risk fusion
 *
 * Implements the risk aggregation formula from the paper:
 * R = 1 - (1 - r_A)(1 - r_I)
 *
 * where:
 * - r_A = application-layer risk (max of all 5 detection layers)
 * - r_I = infrastructure-layer risk (network anomaly score)
 *
 * This combines independent evidence sources to produce a final risk score.
 */

import { RiskScore, ThreatDetection } from '../types';

export class RiskAggregator {
  // Decision thresholds (operationally tuned; recalibrate for production)
  private blockThreshold = 0.85;      // High confidence threat
  private reviewThreshold = 0.65;     // Uncertain; route to human analyst
  private allowThreshold = 0.0;       // Below review threshold; allow

  /**
   * Aggregate threats from application and infrastructure layers
   * Returns overall risk score and recommendation (ALLOW | REVIEW | BLOCK)
   *
   * Formula: R = 1 - (1 - r_A)(1 - r_I)
   * where r_A = max severity from application layer
   *       r_I = max severity from infrastructure layer
   *
   * This ensures partial signals from one layer propagate meaningfully
   * even if the other layer detects nothing.
   */
  aggregate(
    applicationThreats: ThreatDetection[],
    infrastructureThreats: ThreatDetection[]
  ): RiskScore {
    const applicationScore = this.calculateApplicationScore(applicationThreats);
    const infrastructureScore = this.calculateInfrastructureScore(infrastructureThreats);

    // Evidence fusion: combine independent observation planes
    const overallScore = 1 - (1 - applicationScore) * (1 - infrastructureScore);

    // Three-tier decision policy
    let recommendation: 'allow' | 'review' | 'block';
    if (overallScore >= this.blockThreshold) {
      recommendation = 'block';  // High-confidence threat; auto-block
    } else if (overallScore >= this.reviewThreshold) {
      recommendation = 'review'; // Uncertain; escalate to human analyst
    } else {
      recommendation = 'allow';  // Low risk; proceed
    }

    return {
      overallScore: Math.round(overallScore * 100) / 100,
      applicationScore: Math.round(applicationScore * 100) / 100,
      infrastructureScore: Math.round(infrastructureScore * 100) / 100,
      recommendation
    };
  }

  /**
   * Calculate application-layer risk as max severity from all layers
   * Layer 1: Pattern matching
   * Layer 2: Entropy analysis
   * Layer 3: Structural analysis
   * Layer 4: Injection markers
   * Layer 5: Semantic analysis
   * + Data exfiltration monitoring
   */
  private calculateApplicationScore(threats: ThreatDetection[]): number {
    if (threats.length === 0) {
      return 0;
    }

    // Map severity to numeric score
    let maxScore = 0;

    for (const threat of threats) {
      let score = 0;

      switch (threat.severity) {
        case 'critical':
          score = 0.95;
          break;
        case 'high':
          score = 0.7;
          break;
        case 'medium':
          score = 0.4;
          break;
        case 'low':
          score = 0.1;
          break;
      }

      // Weight by threat type
      if (threat.type === 'data_exfiltration') {
        score *= 1.2; // Exfiltration is critical
      }

      maxScore = Math.max(maxScore, score);
    }

    // Cap at 1.0
    return Math.min(maxScore, 1.0);
  }

  /**
   * Calculate infrastructure-layer risk from network anomalies
   * Only network_anomaly type threats contribute to this layer
   *
   * Note: Network-level detection is behavioral and heuristic-based.
   * Legitimate high-volume operations (bulk downloads, API bursts) may trigger
   * false positives. The 0.8 discount factor reflects lower confidence
   * compared to application-layer semantic analysis.
   */
  private calculateInfrastructureScore(threats: ThreatDetection[]): number {
    const networkThreats = threats.filter((t) => t.type === 'network_anomaly');

    if (networkThreats.length === 0) {
      return 0;
    }

    let maxScore = 0;

    for (const threat of networkThreats) {
      let score = 0;

      switch (threat.severity) {
        case 'critical':
          score = 0.95;
          break;
        case 'high':
          score = 0.7;
          break;
        case 'medium':
          score = 0.4;
          break;
        case 'low':
          score = 0.1;
          break;
      }

      maxScore = Math.max(maxScore, score);
    }

    // Confidence discount: infrastructure signals are lower-confidence than
    // application-layer analysis. Apply 0.8 multiplier to avoid over-weighting
    // network anomalies which may be benign (e.g., legitimate bulk operations).
    return Math.min(maxScore * 0.8, 1.0);
  }

  /**
   * Allow operators to recalibrate thresholds for their own risk tolerance
   */
  setThresholds(allow: number, review: number, block: number): void {
    this.allowThreshold = allow;
    this.reviewThreshold = review;
    this.blockThreshold = block;
  }

  /**
   * Explain the risk decision with transparency
   * Helps operators understand why a request was flagged
   */
  explainRisk(riskScore: RiskScore, applicationThreats: ThreatDetection[], infrastructureThreats: ThreatDetection[]): string {
    let explanation = `Risk Assessment: ${riskScore.recommendation.toUpperCase()}\n`;
    explanation += `Overall Score: ${riskScore.overallScore} `;

    if (riskScore.overallScore >= 0.85) {
      explanation += '(CRITICAL - Multiple detection layers triggered)\n';
    } else if (riskScore.overallScore >= 0.65) {
      explanation += '(SUSPICIOUS - Route to human review)\n';
    } else {
      explanation += '(LOW - Within acceptable risk envelope)\n';
    }

    explanation += `\nApplication Layer: ${riskScore.applicationScore} `;
    if (applicationThreats.length > 0) {
      explanation += `(${applicationThreats.length} threats detected)\n`;
      for (const threat of applicationThreats.slice(0, 3)) {
        explanation += `  - [${threat.severity.toUpperCase()}] ${threat.message}\n`;
      }
      if (applicationThreats.length > 3) {
        explanation += `  ... and ${applicationThreats.length - 3} more\n`;
      }
    } else {
      explanation += '(No threats detected)\n';
    }

    explanation += `\nInfrastructure Layer: ${riskScore.infrastructureScore} `;
    if (infrastructureThreats.length > 0) {
      explanation += `(${infrastructureThreats.length} anomalies detected)\n`;
      for (const threat of infrastructureThreats.slice(0, 2)) {
        explanation += `  - [${threat.severity.toUpperCase()}] ${threat.message}\n`;
      }
      if (infrastructureThreats.length > 2) {
        explanation += `  ... and ${infrastructureThreats.length - 2} more\n`;
      }
    } else {
      explanation += '(No anomalies detected)\n';
    }

    explanation += `\nFormula: R = 1 - (1 - ${riskScore.applicationScore})(1 - ${riskScore.infrastructureScore}) = ${riskScore.overallScore}`;

    return explanation;
  }
}
