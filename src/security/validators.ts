import { SensitivityLabel } from '../types';

/**
 * Validates credit card number using Luhn algorithm
 * https://en.wikipedia.org/wiki/Luhn_algorithm
 */
export function validateLuhn(cardNumber: string): boolean {
  const sanitized = cardNumber.replace(/\s+/g, '').replace(/-/g, '');

  if (!/^\d+$/.test(sanitized) || sanitized.length < 13) {
    return false;
  }

  let sum = 0;
  let isEven = false;

  for (let i = sanitized.length - 1; i >= 0; i--) {
    let digit = parseInt(sanitized[i], 10);

    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

/**
 * Validates IBAN using MOD97 algorithm
 * https://en.wikipedia.org/wiki/International_Bank_Account_Number
 */
export function validateMOD97(iban: string): boolean {
  const sanitized = iban.replace(/\s+/g, '').toUpperCase();

  // Check format: 2 letters, 2 digits, then alphanumeric
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$/.test(sanitized)) {
    return false;
  }

  // Move first 4 chars to end
  const rearranged = sanitized.slice(4) + sanitized.slice(0, 4);

  // Replace letters with numbers (A=10, B=11, ..., Z=35)
  const numeric = rearranged.replace(/[A-Z]/g, (char) => {
    return (char.charCodeAt(0) - 55).toString();
  });

  // Calculate mod 97
  let remainder = 0;
  for (const digit of numeric) {
    remainder = (remainder * 10 + parseInt(digit, 10)) % 97;
  }

  return remainder === 1;
}

/**
 * Calculate sensitivity label based on detected data types
 */
export function calculateSensitivityLabel(types: string[]): SensitivityLabel {
  const criticalTypes = new Set([
    'private_key',
    'ssn',
    'health_card',
    'bitcoin_address',
    'ethereum_address'
  ]);

  const highTypes = new Set([
    'credit_card',
    'iban',
    'bank_account',
    'database_url',
    'password'
  ]);

  const mediumTypes = new Set([
    'email',
    'phone_number',
    'passport',
    'drivers_license',
    'social_insurance_number'
  ]);

  // Check in order of severity
  if (types.some((t) => criticalTypes.has(t))) {
    return 'CRITICAL';
  }
  if (types.some((t) => highTypes.has(t))) {
    return 'HIGH';
  }
  if (types.some((t) => mediumTypes.has(t))) {
    return 'MEDIUM';
  }

  return 'LOW';
}

/**
 * Get risk level (numeric) for a sensitivity label
 */
export function getSensitivityRiskLevel(label: SensitivityLabel): number {
  const riskMap: Record<SensitivityLabel, number> = {
    LOW: 0.1,
    MEDIUM: 0.4,
    HIGH: 0.7,
    CRITICAL: 0.95
  };
  return riskMap[label];
}
