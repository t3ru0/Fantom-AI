/**
 * Typed service boundary for the demo client.
 *
 * The UI currently uses deterministic demo records so reviewers can explore
 * every workflow without an API. These contracts are intentionally shaped so
 * the FastAPI client can replace `demoService` without changing page code.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type RepositorySummary = {
  id: string;
  name: string;
  owner: string;
  language: string;
  findingCount: number;
  riskScore: number;
  lastScannedAt: string;
};

export type FindingSummary = {
  id: string;
  title: string;
  repository: string;
  severity: Severity;
  riskScore: number;
  detectedAt: string;
  owner: string;
};

export type RiskSnapshot = {
  score: number;
  trend: number;
  confidence: number;
  capturedAt: string;
};

export interface FantomService {
  listRepositories(): Promise<RepositorySummary[]>;
  listFindings(): Promise<FindingSummary[]>;
  getRiskSnapshot(): Promise<RiskSnapshot>;
  queueScan(repositoryId?: string): Promise<{ scanId: string }>;
}

export const demoService: FantomService = {
  async listRepositories() {
    return [
      { id: 'atlas-api', name: 'atlas-api', owner: 'acme-platform', language: 'TypeScript', findingCount: 14, riskScore: 81, lastScannedAt: '12 min ago' },
      { id: 'checkout-web', name: 'checkout-web', owner: 'acme-commerce', language: 'React', findingCount: 9, riskScore: 67, lastScannedAt: '18 min ago' },
      { id: 'edge-gateway', name: 'edge-gateway', owner: 'acme-infra', language: 'Go', findingCount: 6, riskScore: 44, lastScannedAt: '23 min ago' },
    ];
  },
  async listFindings() {
    return [
      { id: 'FNT-4821', title: 'Hardcoded AWS access key', repository: 'atlas-api', severity: 'high', riskScore: 9.1, detectedAt: '2h ago', owner: 'Platform' },
      { id: 'FNT-4819', title: 'Prototype pollution in lodash', repository: 'checkout-web', severity: 'high', riskScore: 8.7, detectedAt: '5h ago', owner: 'Commerce' },
    ];
  },
  async getRiskSnapshot() {
    return { score: 42, trend: -8, confidence: 91, capturedAt: '12 min ago' };
  },
  async queueScan(repositoryId) {
    return { scanId: `demo-scan-${repositoryId ?? 'workspace'}-001` };
  },
};