/**
 * EvaluationMetrics - Empirical evaluation framework for AEGIS components
 *
 * This module provides rigorous metrics for assessing detection performance:
 * - True Positive Rate (TPR / Sensitivity): correctly identified threats
 * - False Positive Rate (FPR / 1-Specificity): incorrect threat flags on benign data
 * - Precision: of flagged items, how many were actually threats
 * - F1-Score: harmonic mean of precision and recall
 * - ROC-AUC: area under receiver operating characteristic curve
 *
 * CRITICAL LIMITATION: These metrics are computed on synthetic/curated datasets
 * and may NOT generalize to production workloads. Threshold values derived here
 * should be re-calibrated on operator's own traffic baselines.
 */

export interface EvaluationResult {
  // Classification metrics
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;

  // Derived metrics
  tpr: number; // True Positive Rate (sensitivity): TP / (TP + FN)
  fpr: number; // False Positive Rate: FP / (FP + TN)
  tnr: number; // True Negative Rate (specificity): TN / (FP + TN)
  fnr: number; // False Negative Rate: FN / (TP + FN)
  precision: number; // Positive Predictive Value: TP / (TP + FP)
  recall: number; // Same as TPR
  f1Score: number; // Harmonic mean: 2 * (precision * recall) / (precision + recall)
  accuracy: number; // (TP + TN) / (TP + TN + FP + FN)
  rocAuc?: number; // Area under ROC curve (if scores available)

  // Metadata
  timestamp: Date;
  datasetSize: number;
  positiveCount: number;
  negativeCount: number;
  threshold?: number; // Threshold used for decision boundary
}

export interface ThresholdAnalysis {
  threshold: number;
  tpr: number;
  fpr: number;
  precision: number;
  f1Score: number;
  operatingPoint: 'strict' | 'moderate' | 'lenient';
}

export class EvaluationMetrics {
  /**
   * Compute comprehensive evaluation metrics from predictions
   */
  static computeMetrics(
    predictions: Array<{
      predicted: boolean; // detector output
      actual: boolean; // ground truth
      score?: number; // confidence score for ROC analysis
    }>
  ): EvaluationResult {
    const tp = predictions.filter((p) => p.predicted && p.actual).length;
    const fp = predictions.filter((p) => p.predicted && !p.actual).length;
    const tn = predictions.filter((p) => !p.predicted && !p.actual).length;
    const fn = predictions.filter((p) => !p.predicted && p.actual).length;

    const tpr = tp + fn > 0 ? tp / (tp + fn) : 0;
    const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
    const tnr = fp + tn > 0 ? tn / (fp + tn) : 0;
    const fnr = tp + fn > 0 ? fn / (tp + fn) : 0;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tpr;
    const f1Score =
      precision + recall > 0 ? (2 * (precision * recall)) / (precision + recall) : 0;
    const accuracy = (tp + tn) / (tp + tn + fp + fn);

    const positiveCount = tp + fn;
    const negativeCount = tn + fp;

    return {
      truePositives: tp,
      falsePositives: fp,
      trueNegatives: tn,
      falseNegatives: fn,
      tpr,
      fpr,
      tnr,
      fnr,
      precision,
      recall,
      f1Score,
      accuracy,
      timestamp: new Date(),
      datasetSize: predictions.length,
      positiveCount,
      negativeCount
    };
  }

  /**
   * Perform sensitivity analysis: vary decision threshold and measure impact
   * Useful for understanding how robust the detector is to threshold changes
   */
  static thresholdSensitivityAnalysis(
    predictions: Array<{
      predicted: number; // confidence score [0, 1]
      actual: boolean; // ground truth
    }>,
    thresholdsToTest: number[] = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
  ): ThresholdAnalysis[] {
    return thresholdsToTest.map((threshold) => {
      const binaryPredictions = predictions.map((p) => ({
        predicted: p.predicted >= threshold,
        actual: p.actual,
        score: p.predicted
      }));

      const metrics = this.computeMetrics(binaryPredictions);

      return {
        threshold,
        tpr: metrics.tpr,
        fpr: metrics.fpr,
        precision: metrics.precision,
        f1Score: metrics.f1Score,
        operatingPoint:
          threshold < 0.5 ? 'lenient' : threshold > 0.7 ? 'strict' : 'moderate'
      };
    });
  }

  /**
   * Identify optimal threshold that maximizes F1-score
   * CAVEAT: Optimization on test set risks overfitting. Use on validation set only.
   */
  static findOptimalThreshold(
    predictions: Array<{
      predicted: number;
      actual: boolean;
    }>
  ): { threshold: number; f1Score: number } {
    const analysis = this.thresholdSensitivityAnalysis(
      predictions,
      Array.from({ length: 21 }, (_, i) => i / 20) // 0.0, 0.05, 0.10, ..., 1.0
    );

    const best = analysis.reduce((prev, current) =>
      current.f1Score > prev.f1Score ? current : prev
    );

    return { threshold: best.threshold, f1Score: best.f1Score };
  }

  /**
   * Compute confusion matrix for human interpretation
   */
  static confusionMatrix(
    predictions: Array<{
      predicted: boolean;
      actual: boolean;
    }>
  ): {
    matrix: { tp: number; fp: number; fn: number; tn: number };
    display: string;
  } {
    const metrics = this.computeMetrics(predictions);
    const { truePositives: tp, falsePositives: fp, falseNegatives: fn, trueNegatives: tn } =
      metrics;

    // Display as confusion matrix
    const display = `
Confusion Matrix:
               Predicted Threat    Predicted Benign
Actual Threat        ${tp}                ${fn}
Actual Benign        ${fp}                ${tn}

Interpretation:
- TP (${tp}): Threats correctly detected
- FP (${fp}): False alarms on benign data
- FN (${fn}): Missed threats
- TN (${tn}): Benign data correctly allowed
    `.trim();

    return {
      matrix: { tp, fp, fn, tn },
      display
    };
  }

  /**
   * Format results for reporting
   */
  static formatResults(result: EvaluationResult): string {
    return `
EVALUATION RESULTS
==================

Dataset Size: ${result.datasetSize} samples
  - Threats (positives): ${result.positiveCount}
  - Benign (negatives): ${result.negativeCount}

Detection Performance:
  - True Positive Rate (TPR/Sensitivity): ${(result.tpr * 100).toFixed(1)}%
    [Of actual threats, how many were caught]
  - False Positive Rate (FPR): ${(result.fpr * 100).toFixed(1)}%
    [Of benign samples, how many were incorrectly flagged]
  - Precision: ${(result.precision * 100).toFixed(1)}%
    [Of flagged items, how many were actually threats]
  - Recall: ${(result.recall * 100).toFixed(1)}% (same as TPR)
  - F1-Score: ${result.f1Score.toFixed(3)}
    [Harmonic mean of precision and recall; 1.0 = perfect]
  - Accuracy: ${(result.accuracy * 100).toFixed(1)}%
    [Overall correctness on all samples]

Confusion Matrix:
  - True Positives: ${result.truePositives}
  - False Positives: ${result.falsePositives}
  - True Negatives: ${result.trueNegatives}
  - False Negatives: ${result.falseNegatives}

⚠️  IMPORTANT DISCLAIMERS:
  1. These metrics are derived from synthetic/curated datasets.
  2. Production performance will differ based on real traffic characteristics.
  3. Thresholds and distributions in production may vary significantly.
  4. Re-calibration on operator's own benign baseline is REQUIRED.

Evaluated: ${result.timestamp.toISOString()}
    `.trim();
  }
}
