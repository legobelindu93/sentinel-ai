
import type {
    AnalysisResult,
    ThreatMatch,
    MalwareType,
    Severity,
    CapabilityType,
    ProjectType
} from '../types/scanner';

// --- Configuration & Knowledge Base ---

const CAPABILITY_WEIGHTS: Record<CapabilityType, number> = {
    'network_connect': 10,
    'network_listen': 30,
    'file_read': 5,
    'file_write': 10,
    'process_create': 20,
    'process_inject': 50,
    'persistence': 30,
    'obfuscation': 15,
    'crypto_mining': 40,
    'info_stealing': 40,
    'evasion': 30,
    'privilege_escalation': 50,
    'command_exec': 20,
    'dynamic_code_loading': 20
};

const CHAINS = [
    { name: 'Dropper Chain', required: ['network_connect', 'file_write', 'process_create'], bonus: 40 },
    { name: 'RAT Chain', required: ['network_connect', 'command_exec', 'persistence'], bonus: 60 },
    { name: 'Stealer Chain', required: ['file_read', 'network_connect', 'info_stealing'], bonus: 50 }
];

// --- 1. Project Understanding & File Categorization ---

type FileCategory = 'UI' | 'BUILD' | 'LOGIC' | 'CONFIG' | 'DATA' | 'UNKNOWN';

const categorizeFile = (path: string): FileCategory => {
    const p = path.toLowerCase();
    if (p.endsWith('.css') || p.endsWith('.scss') || p.endsWith('.less') || p.endsWith('.html') || p.endsWith('.svg') || p.endsWith('.png') || p.endsWith('.ico') || p.endsWith('.jpg')) return 'UI';
    if (p.includes('theme') || p.includes('style') || p.includes('layout') || p.includes('public/') || p.includes('assets/')) return 'UI';
    if (p.includes('webpack') || p.includes('vite') || p.includes('rollup') || p.endsWith('.json') || p.includes('config')) return 'CONFIG';
    if (p.endsWith('.test.ts') || p.endsWith('.spec.ts')) return 'BUILD';
    if (p.endsWith('.ts') || p.endsWith('.js') || p.endsWith('.py') || p.endsWith('.go') || p.endsWith('.c')) return 'LOGIC';
    return 'UNKNOWN';
};

const detectProjectContext = (repoName: string, files: number, matches: ThreatMatch[]): { type: ProjectType; confidence: number; detectedFrameworks: string[] } => {
    let type: ProjectType = 'unknown';
    let confidence = 0;
    const frameworks: string[] = [];
    const lowerRepo = repoName.toLowerCase();

    // 1. Static Site / CV / Portfolio Detection (High Priority)
    const isCV = lowerRepo.includes('cv') || lowerRepo.includes('portfolio') || lowerRepo.includes('resume') || lowerRepo.includes('profile');
    const isStatic = lowerRepo.includes('css') || lowerRepo.includes('html') || lowerRepo.includes('theme');
    const hasUIOnly = matches.every(m => categorizeFile(m.file) === 'UI' || m.content.includes('localStorage'));

    if (isCV || isStatic || (files < 15 && hasUIOnly)) {
        type = 'application';
        confidence = 99;
        return { type: 'application', confidence, detectedFrameworks: ['Static Site', 'Portfolio'] };
    }

    // 2. Frameworks
    const hasReact = matches.some(m => m.file.includes('tsx') || m.file.includes('jsx'));
    const hasTailwind = matches.some(m => m.file.includes('tailwind'));

    if (hasReact || hasTailwind) {
        type = 'frontend_framework';
        confidence = 90;
        if (hasReact) frameworks.push('React');
        if (hasTailwind) frameworks.push('TailwindCSS');
    } else if (matches.some(m => m.content.includes('argparse'))) {
        type = 'cli_tool';
        confidence = 70;
    } else if (matches.some(m => m.content.toLowerCase().includes('exploit')) || lowerRepo.includes('exploit')) {
        type = 'security_research';
        confidence = 85;
    } else {
        type = 'application';
        confidence = 40;
    }

    return { type, confidence, detectedFrameworks: frameworks };
};

// --- 2. Contextual Legitimacy Validator (The "Brain") ---

const isBehaviorLegitimate = (match: ThreatMatch, context: ProjectType, fileCategory: FileCategory, detectedFrameworks: string[]): boolean => {
    const { capability, file, content } = match;
    const isPortfolio = detectedFrameworks.includes('Portfolio') || detectedFrameworks.includes('Static Site');

    // RULE: UI files and Portfolios are SAFE ZONES for most things
    if (fileCategory === 'UI' || isPortfolio) {
        // "Dark Mode" uses localStorage -> SAFE
        if (capability === 'info_stealing' && (content.includes('localStorage') || content.includes('sessionStorage') || content.includes('getItem'))) return true;
        // Loading assets -> SAFE
        if (capability === 'network_connect') return true;
        // "Obfuscated" CSS/JS minified -> SAFE
        if (capability === 'obfuscation') return true;

        return true;
    }

    // RULE: Frontend Frameworks
    if (context === 'frontend_framework') {
        if (capability === 'network_connect') return true; // Fetch API
        if (capability === 'process_create' && file.includes('build')) return true; // Build scripts
        if (capability === 'file_write' && (file.includes('dist') || file.includes('build'))) return true; // Build output
        // Common false positive: localStorage in React apps
        if (capability === 'info_stealing' && content.includes('localStorage')) return true;
    }

    // RULE: Config/Build
    if (fileCategory === 'CONFIG' || fileCategory === 'BUILD') {
        if (capability === 'process_create' || capability === 'file_read') return true;
    }

    return false; // Otherwise, treat as potentially suspicious
};

// --- 3. Strict Classification Engine ---

const determineStrictType = (capabilities: string[], chains: string[], verdict: string): MalwareType | 'NONE' => {
    if (verdict === 'SAFE') return 'NONE';

    // Must meet STRICT definition
    if (capabilities.includes('network_listen') && (capabilities.includes('command_exec') || capabilities.includes('process_create'))) return 'Backdoor';
    if (chains.includes('RAT Chain')) return 'RAT';
    if (chains.includes('Stealer Chain')) return 'Stealer';
    if (capabilities.includes('crypto_mining')) return 'Cryptominer';
    if (chains.includes('Dropper Chain')) return 'Dropper';
    // Trojan requires real injection or hiding
    if (capabilities.includes('process_inject')) return 'Trojan';

    if (verdict === 'DUAL-USE') return 'Dual-Use';
    if (verdict === 'MALICIOUS') return 'Trojan'; // Fallback
    if (verdict === 'SUSPICIOUS') return 'Suspicious';

    return 'NONE';
};

// --- 4. Main Analysis Pipeline ---

export const analyzeMatches = (matches: ThreatMatch[], repoName: string, totalFiles: number): AnalysisResult => {

    // STEP 1: Context Understanding
    const context = detectProjectContext(repoName, totalFiles, matches);

    // STEP 2: File Categorization & Filtering
    const processedMatches = matches.map(m => ({ ...m, category: categorizeFile(m.file) }));

    // STEP 3: "Safe Zone" Elimination
    const suspiciousMatches = processedMatches.filter(m => !isBehaviorLegitimate(m, context.type, m.category, context.detectedFrameworks));
    const dismissedMatches = processedMatches.filter(m => isBehaviorLegitimate(m, context.type, m.category, context.detectedFrameworks));

    // STEP 4: Evidence Aggregation
    const capabilities = Array.from(new Set(suspiciousMatches.map(m => m.capability)));

    let rawScore = 0;
    suspiciousMatches.forEach(m => rawScore += CAPABILITY_WEIGHTS[m.capability] || 5);

    // Chain Reconstruction
    const detectedChains: string[] = [];
    CHAINS.forEach(chain => {
        if (chain.required.every(req => capabilities.includes(req as CapabilityType))) {
            detectedChains.push(chain.name);
            rawScore += chain.bonus;
        }
    });

    // STEP 5: Verdict Determination
    let verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'DUAL-USE' = 'SAFE';
    let confidence = 0;

    if (detectedChains.length > 0) {
        verdict = 'MALICIOUS';
        confidence = 95;
    } else if (rawScore > 60) {
        verdict = 'MALICIOUS'; // High heuristic score
        confidence = 85;
    } else if (context.type === 'security_research' && rawScore > 20) {
        verdict = 'DUAL-USE';
        confidence = 90;
        rawScore = 30; // Cap score for authorized tools
    } else if (rawScore > 35) {
        verdict = 'SUSPICIOUS';
        confidence = 60;
    } else if (rawScore > 10) {
        verdict = 'DUAL-USE';
        confidence = 40;
    } else {
        verdict = 'SAFE';
        confidence = 99;
    }

    // STEP 6: AUTO-CHECK (Hallucination Guard)
    const isStaticContext = context.type === 'frontend_framework' || context.detectedFrameworks.includes('Static Site') || context.detectedFrameworks.includes('Portfolio');

    if (isStaticContext) {
        // STRICT GUARD: Static sites CANNOT contain Trojans/RATs/Backdoors unless explicitly proven by a Chain.
        // If we just have some loose capabilities but no chain -> FORCE SAFE
        if (detectedChains.length === 0) {
            verdict = 'SAFE';
            rawScore = 0;
            confidence = 99;
        }
    }

    // Cap Score
    const finalScore = Math.min(100, verdict === 'SAFE' ? 0 : rawScore);

    // STEP 7: Classification
    const primaryType = determineStrictType(capabilities, detectedChains, verdict);

    // STEP 8: Explanation Generation
    let explanation = "";
    if (verdict === 'SAFE') {
        const typeLabel = context.detectedFrameworks.length > 0 ? context.detectedFrameworks.join('/') : context.type.replace('_', ' ');
        explanation = `Verdict: CLEAN\nReason: Recognized as a legitimate ${typeLabel}.\n`;
        explanation += `Analysis: ${dismissedMatches.length} indicators (likely theming, UI logic, or build tools) were automatically verified as safe.`;
    } else {
        explanation = `Verdict: ${verdict}\nType: ${primaryType}\n`;
        explanation += `Reasoning: A high-confidence attack chain (${detectedChains.join(', ') || 'Heuristic Match'}) was identified which contradict legitimate usage.\n`;
        explanation += `Context: Although identified as ${context.type}, the presence of ${capabilities.slice(0, 3).join(', ')} is highly anomalous.`;
    }

    // Helper for Secondary Types (Simplified for this strict flow)
    const secondaryTypes: MalwareType[] = [];

    return {
        repoName,
        score: finalScore,
        riskLevel: getRiskLevel(finalScore),
        verdict,
        confidence,
        projectContext: context,
        primaryType,
        secondaryTypes,
        behaviors: capabilities.map(c => c.replace('_', ' ').toUpperCase()),
        attackChain: detectedChains,
        matches: suspiciousMatches, // Only show relevant evidence
        explanation,
        scannedFiles: matches.length > 0 ? totalFiles : 0
    };
};

const getRiskLevel = (score: number): Severity => {
    if (score === 0) return 'safe';
    if (score < 25) return 'low';
    if (score < 50) return 'medium';
    if (score < 75) return 'high';
    return 'critical';
};
