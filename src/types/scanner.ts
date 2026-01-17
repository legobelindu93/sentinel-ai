export type Severity = 'safe' | 'low' | 'medium' | 'high' | 'critical';

export type MalwareType =
    | 'Trojan'
    | 'Backdoor'
    | 'RAT'
    | 'Stealer'
    | 'Spyware'
    | 'Cryptominer'
    | 'Dropper'
    | 'Loader'
    | 'Rootkit'
    | 'Worm'
    | 'Adware'
    | 'Ransomware'
    | 'Botnet'
    | 'Dual-Use'
    | 'Safe'
    | 'Suspicious';

export type CapabilityType =
    | 'network_connect'
    | 'network_listen'
    | 'file_read'
    | 'file_write'
    | 'process_create'
    | 'process_inject'
    | 'persistence'
    | 'obfuscation'
    | 'crypto_mining'
    | 'info_stealing'
    | 'evasion'
    | 'privilege_escalation'
    | 'command_exec'
    | 'dynamic_code_loading';

export interface ThreatMatch {
    ruleId: string;
    severity: Severity;
    line: number;
    content: string;
    file: string;
    capability: CapabilityType;
    description: string;
}

export interface Rule {
    id: string;
    language: string | 'all';
    pattern: RegExp;
    severity: Severity;
    capability: CapabilityType;
    description: string;
}

export interface AnalysisResult {
    repoName: string;
    score: number; // 0-100
    riskLevel: Severity;
    verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'DUAL-USE';
    confidence: number; // 0-100%
    projectContext: {
        type: ProjectType;
        confidence: number;
        detectedFrameworks: string[];
        isPopular?: boolean;
    };
    primaryType: MalwareType | 'NONE';
    secondaryTypes: MalwareType[];
    behaviors: string[];
    attackChain: string[];
    matches: ThreatMatch[];
    explanation: string;
    scannedFiles: number;
}

export type ProjectType = 'frontend_framework' | 'backend_framework' | 'cli_tool' | 'security_research' | 'application' | 'library' | 'unknown';

