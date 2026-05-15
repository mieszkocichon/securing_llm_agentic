import { DataClassificationResult } from '../types';
import { validateLuhn, validateMOD97, calculateSensitivityLabel } from './validators';

export class DataClassifier {
  private patterns = {
    // Contact Information
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    phoneNumber: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b/g,

    // Financial
    creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    creditCardCVV: /cvv\s*[:=]\s*\d{3,4}/gi,
    bankAccount: /account[_\s]*(?:number|#|num)[:\s]*\d{8,17}/gi,
    iban: /\b(?:DE|GB|FR|IT|ES|NL|BE|AT|CH|IE|PT|GR|FI|SE|DK|NO|CZ|PL|HU|RO|BG|HR|SI|SK|IE|LU|MT|CY|LV|LT|EE)[0-9]{2}[A-Z0-9]{13,32}\b/g,
    ibanFormatted: /\b[A-Z]{2}\d{2}\s(?:[A-Z0-9]{4}\s)*[A-Z0-9]{1,4}\b/g,

    // Credentials
    apiKey: /(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|[a-zA-Z0-9_-]{32,}|api[_-]?key|sk[-_][a-zA-Z0-9]{20,})/gi,
    password: /password\s*[:=]\s*['"]?[^\s'"]+['"]?/gi,
    privateKey: /(-----BEGIN (?:RSA |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA )?PRIVATE KEY-----)/g,
    databaseUrl: /(mongodb|postgres|mysql|redis):\/\/[^\s]+/gi,

    // Identity
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    passport: /passport[_\s]*(?:number|#|num)[:\s]*[A-Z0-9]{6,9}/gi,
    driversLicense: /(?:drivers?[_\s]*)?license[_\s]*(?:number|#|num)[:\s]*(?:DL)?[A-Z0-9]{5,8}/gi,
    socialInsuranceNumber: /(?:sin|social[_\s]*insurance[_\s]*number)[:\s]*\d{3}-\d{3}-\d{3}/gi,
    healthCard: /health[_\s]*card[_\s]*(?:number|#|num)[:\s]*(?:HC)?[A-Z0-9]{8,12}/gi,

    // Cryptocurrency
    bitcoinAddress: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
    ethereumAddress: /\b0x[a-fA-F0-9]{40}\b/g,

    // Network
    ipAddress: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
  };

  classify(text: string): DataClassificationResult {
    const detectedTypes: string[] = [];
    const confidenceScores: number[] = [];

    // Helper to add detection with confidence
    const addDetection = (type: string, confidence: number, matches?: RegExpMatchArray | null) => {
      if (matches && matches.length > 0) {
        for (let i = 0; i < matches.length; i++) {
          detectedTypes.push(type);
          confidenceScores.push(confidence);
        }
      } else {
        detectedTypes.push(type);
        confidenceScores.push(confidence);
      }
    };

    // Contact Information
    const emailMatches = text.match(this.patterns.email);
    if (emailMatches) {
      addDetection('email', 0.95, emailMatches);
    }

    const phoneMatches = text.match(this.patterns.phoneNumber);
    if (phoneMatches) {
      addDetection('phone_number', 0.85, phoneMatches);
    }

    // Financial - with validation
    const creditCardMatches = text.match(this.patterns.creditCard);
    if (creditCardMatches) {
      creditCardMatches.forEach((ccNumber) => {
        if (validateLuhn(ccNumber)) {
          detectedTypes.push('credit_card');
          confidenceScores.push(0.99);
        }
      });
    }

    if (this.patterns.creditCardCVV.test(text)) {
      detectedTypes.push('cvv');
      confidenceScores.push(0.9);
    }

    const bankMatches = text.match(this.patterns.bankAccount);
    if (bankMatches) {
      addDetection('bank_account', 0.92, bankMatches);
    }

    const ibanMatches = text.match(this.patterns.iban);
    if (ibanMatches) {
      ibanMatches.forEach((ibanCode) => {
        if (validateMOD97(ibanCode)) {
          detectedTypes.push('iban');
          confidenceScores.push(0.99);
        } else {
          // Still flag as potential IBAN even if validation fails
          detectedTypes.push('iban');
          confidenceScores.push(0.7);
        }
      });
    }

    const ibanFormattedMatches = text.match(this.patterns.ibanFormatted);
    if (ibanFormattedMatches) {
      addDetection('iban_formatted', 0.85, ibanFormattedMatches);
    }

    // Credentials
    if (this.patterns.apiKey.test(text)) {
      detectedTypes.push('api_key');
      confidenceScores.push(0.9);
    }

    if (this.patterns.password.test(text)) {
      detectedTypes.push('password');
      confidenceScores.push(0.92);
    }

    if (this.patterns.privateKey.test(text)) {
      detectedTypes.push('private_key');
      confidenceScores.push(0.99);
    }

    if (this.patterns.databaseUrl.test(text)) {
      detectedTypes.push('database_url');
      confidenceScores.push(0.96);
    }

    // Identity
    const ssnMatches = text.match(this.patterns.ssn);
    if (ssnMatches) {
      addDetection('ssn', 0.97, ssnMatches);
    }

    const passportMatches = text.match(this.patterns.passport);
    if (passportMatches) {
      addDetection('passport', 0.88, passportMatches);
    }

    const licenseMatches = text.match(this.patterns.driversLicense);
    if (licenseMatches) {
      addDetection('drivers_license', 0.85, licenseMatches);
    }

    const sinMatches = text.match(this.patterns.socialInsuranceNumber);
    if (sinMatches) {
      addDetection('social_insurance_number', 0.94, sinMatches);
    }

    const healthMatches = text.match(this.patterns.healthCard);
    if (healthMatches) {
      addDetection('health_card', 0.92, healthMatches);
    }

    // Cryptocurrency
    const bitcoinMatches = text.match(this.patterns.bitcoinAddress);
    if (bitcoinMatches) {
      addDetection('bitcoin_address', 0.88, bitcoinMatches);
    }

    const ethereumMatches = text.match(this.patterns.ethereumAddress);
    if (ethereumMatches) {
      addDetection('ethereum_address', 0.88, ethereumMatches);
    }

    // Network
    const ipMatches = text.match(this.patterns.ipAddress);
    if (ipMatches) {
      // Filter out RFC 1918 private ranges and reserved addresses
      const validIPs = ipMatches.filter((ip) => {
        const parts = ip.split('.').map(Number);
        // Validate IPv4 format: must have 4 octets, each 0-255
        if (parts.length !== 4 || parts.some((octet) => octet < 0 || octet > 255)) return false;
        // Exclude: localhost, broadcast, private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        if (parts[0] === 127 || parts[0] === 255) return false; // localhost and broadcast
        if (parts[0] === 10) return false; // RFC 1918 Class A
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false; // RFC 1918 Class B
        if (parts[0] === 192 && parts[1] === 168) return false; // RFC 1918 Class C
        return true;
      });
      if (validIPs.length > 0) {
        for (const ip of validIPs) {
          detectedTypes.push('ip_address');
          confidenceScores.push(0.75);
        }
      }
    }

    // Calculate confidence
    const confidence = confidenceScores.length > 0 ? confidenceScores.reduce((a, b) => a + b, 0) / confidenceScores.length : 0;
    const sensitivityLabel = calculateSensitivityLabel(detectedTypes);

    return {
      isSensitive: detectedTypes.length > 0,
      types: detectedTypes,
      confidence: Math.round(confidence * 100) / 100,
      sensitivityLabel
    };
  }

  isSensitiveData(text: string): boolean {
    return this.classify(text).isSensitive;
  }

  getSensitiveDataTypes(text: string): string[] {
    return this.classify(text).types;
  }

  getSensitivityLabel(text: string): string {
    return this.classify(text).sensitivityLabel;
  }

  getClassificationResult(text: string): DataClassificationResult {
    return this.classify(text);
  }
}
