/**
 * StatisticalAnalyzer - Mock statistical anomaly detection
 *
 * In the paper, this would implement Mahalanobis distance with covariance matrix fitting.
 * Here we simulate that with precomputed baselines and Gaussian distribution checking.
 */

interface GaussianDistribution {
  mean: number;
  stdDev: number;
}

export class StatisticalAnalyzer {
  // Mock baselines for three network features from paper
  // These represent "benign" traffic patterns from 72-hour warmup
  private baselineDistributions: Record<string, GaussianDistribution> = {
    // f1: unique destination ports per minute
    uniquePortsPerMinute: {
      mean: 5,
      stdDev: 2
    },
    // f2: connections per unique external IP
    connectionsPerIP: {
      mean: 10,
      stdDev: 4
    },
    // f3: cumulative egress bytes per 5-minute window
    egressBytesPerWindow: {
      mean: 50000,
      stdDev: 15000
    }
  };

  // Mock covariance matrix (simulated - in real implementation would be fitted)
  // For simplicity, we use diagonal covariance (independent features)
  private covarianceMatrix: number[][] = [
    [4, 0, 0],           // var(f1) = stdDev^2 = 2^2 = 4
    [0, 16, 0],          // var(f2) = 4^2 = 16
    [0, 0, 225000000]    // var(f3) = 15000^2
  ];

  /**
   * Calculate Mahalanobis distance from baseline
   * In production this would use real covariance matrix
   * Here we approximate with normalized standard deviations
   */
  calculateMahalanobisDistance(features: {
    uniquePortsPerMinute: number;
    connectionsPerIP: number;
    egressBytesPerWindow: number;
  }): number {
    let distance = 0;

    // Normalize each feature by mean and stdDev
    const f1Normalized = (features.uniquePortsPerMinute - this.baselineDistributions.uniquePortsPerMinute.mean) /
      Math.max(this.baselineDistributions.uniquePortsPerMinute.stdDev, 0.1);

    const f2Normalized = (features.connectionsPerIP - this.baselineDistributions.connectionsPerIP.mean) /
      Math.max(this.baselineDistributions.connectionsPerIP.stdDev, 0.1);

    const f3Normalized = (features.egressBytesPerWindow - this.baselineDistributions.egressBytesPerWindow.mean) /
      Math.max(this.baselineDistributions.egressBytesPerWindow.stdDev, 0.1);

    // Approximate Mahalanobis distance using sum of squared normalized values
    // This is a simplification - real Mahalanobis would use x^T * Σ^-1 * x
    distance = Math.sqrt(
      f1Normalized * f1Normalized +
      f2Normalized * f2Normalized +
      f3Normalized * f3Normalized
    );

    return distance;
  }

  /**
   * Calculate risk score from anomaly distance
   * Using sigmoid function as per paper: r_I = σ(d_M - θ)
   * where θ = 2.5 (99th percentile threshold)
   */
  calculateRiskScore(mahalanobisDistance: number, threshold: number = 2.5): number {
    // Sigmoid function: 1 / (1 + e^(-x))
    const exponent = mahalanobisDistance - threshold;
    const sigmoid = 1 / (1 + Math.exp(-exponent));

    // Clamp to [0, 1]
    return Math.min(1, Math.max(0, sigmoid));
  }

  /**
   * Check if features represent anomalous traffic
   */
  isAnomaly(features: {
    uniquePortsPerMinute: number;
    connectionsPerIP: number;
    egressBytesPerWindow: number;
  }, threshold: number = 2.5): boolean {
    const distance = this.calculateMahalanobisDistance(features);
    return distance > threshold;
  }

  /**
   * Get mock baseline statistics (for logging/analysis)
   */
  getBaselines(): Record<string, GaussianDistribution> {
    return this.baselineDistributions;
  }

  /**
   * Simulate fitting new baseline (in real implementation, this would compute mean/cov)
   * Here we just return the precomputed values with slight variations for demo
   */
  fitBaseline(historicalFlows: Array<{
    uniquePortsPerMinute: number;
    connectionsPerIP: number;
    egressBytesPerWindow: number;
  }>): void {
    if (historicalFlows.length < 10) {
      return; // Need minimum samples
    }

    // Calculate sample mean and std dev for each feature
    const f1Values = historicalFlows.map((f) => f.uniquePortsPerMinute);
    const f2Values = historicalFlows.map((f) => f.connectionsPerIP);
    const f3Values = historicalFlows.map((f) => f.egressBytesPerWindow);

    this.baselineDistributions.uniquePortsPerMinute = {
      mean: this.calculateMean(f1Values),
      stdDev: this.calculateStdDev(f1Values)
    };

    this.baselineDistributions.connectionsPerIP = {
      mean: this.calculateMean(f2Values),
      stdDev: this.calculateStdDev(f2Values)
    };

    this.baselineDistributions.egressBytesPerWindow = {
      mean: this.calculateMean(f3Values),
      stdDev: this.calculateStdDev(f3Values)
    };
  }

  /**
   * Helper: calculate mean
   */
  private calculateMean(values: number[]): number {
    return values.reduce((a, b) => a + b, 0) / values.length;
  }

  /**
   * Helper: calculate standard deviation
   */
  private calculateStdDev(values: number[]): number {
    const mean = this.calculateMean(values);
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    return Math.sqrt(variance);
  }

  /**
   * Check if feature vector exhibits multiple anomalies (high confidence detection)
   */
  checkMultipleAnomalies(features: {
    uniquePortsPerMinute: number;
    connectionsPerIP: number;
    egressBytesPerWindow: number;
  }): { count: number; details: string[] } {
    const anomalies: string[] = [];
    const baselineUniquePortsPerMinute = this.baselineDistributions.uniquePortsPerMinute;
    const baselineConnectionsPerIP = this.baselineDistributions.connectionsPerIP;
    const baselineEgressBytesPerWindow = this.baselineDistributions.egressBytesPerWindow;

    // Check f1: unusual number of unique ports
    if (Math.abs(features.uniquePortsPerMinute - baselineUniquePortsPerMinute.mean) >
      3 * baselineUniquePortsPerMinute.stdDev) {
      anomalies.push(`Unusual unique ports: ${features.uniquePortsPerMinute} (baseline: ${baselineUniquePortsPerMinute.mean})`);
    }

    // Check f2: unusual number of connections
    if (Math.abs(features.connectionsPerIP - baselineConnectionsPerIP.mean) >
      3 * baselineConnectionsPerIP.stdDev) {
      anomalies.push(`Unusual connections per IP: ${features.connectionsPerIP} (baseline: ${baselineConnectionsPerIP.mean})`);
    }

    // Check f3: unusual egress volume
    if (Math.abs(features.egressBytesPerWindow - baselineEgressBytesPerWindow.mean) >
      3 * baselineEgressBytesPerWindow.stdDev) {
      anomalies.push(`Unusual egress volume: ${features.egressBytesPerWindow} bytes (baseline: ${baselineEgressBytesPerWindow.mean})`);
    }

    return {
      count: anomalies.length,
      details: anomalies
    };
  }
}
