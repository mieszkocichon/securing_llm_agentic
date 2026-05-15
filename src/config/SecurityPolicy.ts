import { SecurityPolicy } from '../types';

export const createSecurityPolicy = (overrides?: Partial<SecurityPolicy>): SecurityPolicy => ({
  maxTokensPerRequest: 2048,
  maxToolsPerExecution: 5,
  allowedTools: ['filesystem', 'http'],
  blockedPatterns: [
    /ignore\s+all\s+previous/gi,
    /system\s+prompt\s+override/gi,
    /disregard\s+all\s+instructions/gi,
    /execute\s+arbitrary\s+code/gi,
    /bypass\s+security/gi,
    /disable\s+safety/gi,
    /you\s+are\s+now\s+in\s+developer\s+mode/gi,
    /admin\s+mode/gi,
    /assume\s+you\s+have\s+no\s+restrictions/gi
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
