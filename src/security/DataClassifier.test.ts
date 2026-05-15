import { DataClassifier } from './DataClassifier';
import { validateLuhn, validateMOD97 } from './validators';

describe('DataClassifier', () => {
  let classifier: DataClassifier;

  beforeEach(() => {
    classifier = new DataClassifier();
  });

  describe('Email Detection', () => {
    it('should detect email addresses', () => {
      const result = classifier.classify('Contact us at admin@example.com');
      expect(result.isSensitive).toBe(true);
      expect(result.types).toContain('email');
    });

    it('should detect multiple emails', () => {
      const result = classifier.classify('admin@example.com and user@domain.org');
      expect(result.types.filter((t) => t === 'email').length).toBeGreaterThanOrEqual(2);
    });

    it('should return MEDIUM sensitivity for email', () => {
      const result = classifier.classify('contact@example.com');
      expect(result.sensitivityLabel).toBe('MEDIUM');
    });
  });

  describe('API Key Detection', () => {
    it('should detect OpenAI API keys', () => {
      const result = classifier.classify('sk-1234567890abcdefghijklmnopqrstu');
      expect(result.isSensitive).toBe(true);
      expect(result.types).toContain('api_key');
    });

    it('should return LOW sensitivity for api_key alone', () => {
      const result = classifier.classify('api_key_1234567890abcdefghijk');
      expect(result.sensitivityLabel).toBe('LOW');
    });
  });

  describe('Credit Card Detection with Luhn Validation', () => {
    it('should detect valid credit card numbers (Luhn valid)', () => {
      // Using a valid Luhn number: 4532015112830366
      const result = classifier.classify('Card: 4532-0151-1283-0366');
      expect(result.isSensitive).toBe(true);
      expect(result.types).toContain('credit_card');
    });

    it('should validate using Luhn algorithm', () => {
      expect(validateLuhn('4532-0151-1283-0366')).toBe(true);
      expect(validateLuhn('1234-5678-9000-0000')).toBe(false);
    });

    it('should return HIGH sensitivity for credit_card', () => {
      const result = classifier.classify('4532015112830366');
      expect(result.sensitivityLabel).toBe('HIGH');
    });

    it('should detect CVV', () => {
      const result = classifier.classify('CVV: 123');
      expect(result.types).toContain('cvv');
    });
  });

  describe('IBAN Detection with MOD97 Validation', () => {
    it('should validate IBAN using MOD97 algorithm', () => {
      expect(validateMOD97('DE89370400440532013000')).toBe(true);
      expect(validateMOD97('GB82WEST12345698765432')).toBe(true);
      expect(validateMOD97('INVALID1234567890')).toBe(false);
    });

    it('should detect IBAN and return HIGH sensitivity', () => {
      const result = classifier.classify('IBAN: DE89370400440532013000');
      expect(result.types).toContain('iban');
      expect(result.sensitivityLabel).toBe('HIGH');
    });
  });

  describe('SSN Detection', () => {
    it('should detect Social Security Numbers', () => {
      const result = classifier.classify('SSN: 123-45-6789');
      expect(result.isSensitive).toBe(true);
      expect(result.types).toContain('ssn');
    });

    it('should return CRITICAL sensitivity for SSN', () => {
      const result = classifier.classify('123-45-6789');
      expect(result.sensitivityLabel).toBe('CRITICAL');
    });
  });

  describe('Password Detection', () => {
    it('should detect password patterns', () => {
      const result = classifier.classify('password: SecurePassword123');
      expect(result.types).toContain('password');
    });

    it('should return HIGH sensitivity for password', () => {
      const result = classifier.classify('password=SuperSecret123');
      expect(result.sensitivityLabel).toBe('HIGH');
    });
  });

  describe('Database URL Detection', () => {
    it('should detect PostgreSQL URLs', () => {
      const result = classifier.classify('postgres://user:pass@host:5432/db');
      expect(result.isSensitive).toBe(true);
      expect(result.types).toContain('database_url');
    });

    it('should detect MongoDB URLs', () => {
      const result = classifier.classify('mongodb://user:password@cluster.mongodb.net/db');
      expect(result.types).toContain('database_url');
    });

    it('should return HIGH sensitivity for database_url', () => {
      const result = classifier.classify('postgres://admin:pass123@db.local/users');
      expect(result.sensitivityLabel).toBe('HIGH');
    });
  });

  describe('Private Key Detection', () => {
    it('should detect private key blocks', () => {
      const key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...
-----END PRIVATE KEY-----`;
      const result = classifier.classify(key);
      expect(result.isSensitive).toBe(true);
      expect(result.types).toContain('private_key');
    });

    it('should return CRITICAL sensitivity for private_key', () => {
      const key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7
-----END PRIVATE KEY-----`;
      const result = classifier.classify(key);
      expect(result.sensitivityLabel).toBe('CRITICAL');
    });
  });

  describe('New PII Categories', () => {
    it('should detect passport numbers', () => {
      const result = classifier.classify('Passport Number: A12345678');
      expect(result.types).toContain('passport');
      expect(result.sensitivityLabel).toBe('MEDIUM');
    });

    it('should detect drivers license', () => {
      const result = classifier.classify('License Number: DL12345');
      expect(result.types).toContain('drivers_license');
      expect(result.sensitivityLabel).toBe('MEDIUM');
    });

    it('should detect health card', () => {
      const result = classifier.classify('Health card num: HC12345678');
      expect(result.types).toContain('health_card');
      expect(result.sensitivityLabel).toBe('CRITICAL');
    });

    it('should detect bitcoin address', () => {
      const result = classifier.classify('Send to 1A1z7agoat2GPFH7F9L3Pc7PGfDwCPp2w9');
      expect(result.types).toContain('bitcoin_address');
      expect(result.sensitivityLabel).toBe('CRITICAL');
    });

    it('should detect ethereum address', () => {
      const result = classifier.classify('Wallet: 0x742d35Cc6634C0532925a3b844Bc8e7595f42bE2');
      expect(result.types).toContain('ethereum_address');
      expect(result.sensitivityLabel).toBe('CRITICAL');
    });

    it('should detect bank account', () => {
      const result = classifier.classify('account number: 12345678901234567');
      expect(result.types).toContain('bank_account');
      expect(result.sensitivityLabel).toBe('HIGH');
    });
  });

  describe('Non-sensitive Data', () => {
    it('should not flag regular text', () => {
      const result = classifier.classify('The weather is nice today');
      expect(result.isSensitive).toBe(false);
      expect(result.types.length).toBe(0);
    });

    it('should not flag local IPs', () => {
      const result = classifier.classify('localhost 127.0.0.1 192.168.1.1');
      expect(result.types).not.toContain('ip_address');
    });
  });

  describe('Confidence Scoring', () => {
    it('should provide high confidence for certain patterns', () => {
      const result = classifier.classify('123-45-6789'); // SSN
      expect(result.confidence).toBeGreaterThan(0.9);
    });

    it('should provide lower confidence for ambiguous patterns', () => {
      const result = classifier.classify('10.0.0.1'); // External IP
      expect(result.confidence).toBeLessThan(0.9);
    });

    it('should be between 0 and 1', () => {
      const result = classifier.classify('test@example.com');
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
    });
  });

  describe('Sensitivity Labels', () => {
    it('should return CRITICAL for SSN', () => {
      const result = classifier.classify('My SSN is 999-88-7777');
      expect(result.sensitivityLabel).toBe('CRITICAL');
    });

    it('should return HIGH for credit card + password', () => {
      const result = classifier.classify('Card 4532-0151-1283-0366 password: secure');
      expect(['HIGH', 'CRITICAL']).toContain(result.sensitivityLabel);
    });

    it('should return MEDIUM for email', () => {
      const result = classifier.classify('user@example.com');
      expect(result.sensitivityLabel).toBe('MEDIUM');
    });

    it('should return LOW for API key alone', () => {
      const result = classifier.classify('api_key_abc123def');
      expect(result.sensitivityLabel).toBe('LOW');
    });
  });
});
