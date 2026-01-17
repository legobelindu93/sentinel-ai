import { RULES } from './rules';
import type { ThreatMatch } from '../types/scanner';

const EXTENSION_MAP: Record<string, string> = {
    js: 'javascript', tjs: 'javascript', jsx: 'javascript', ts: 'javascript', tsx: 'javascript',
    py: 'python',
    ps1: 'powershell',
    sh: 'bash', bash: 'bash',
    c: 'c', cpp: 'c', h: 'c',
    go: 'go',
    php: 'php',
    bat: 'batch', cmd: 'batch',
};

export const scanFile = (fileName: string, content: string): ThreatMatch[] => {
    // 1. Safety Check: Skip massive files (limit to ~2MB for browser safety)
    if (content.length > 2 * 1024 * 1024) {
        console.warn(`Skipping too large file: ${fileName}`);
        return [];
    }

    const extension = fileName.split('.').pop()?.toLowerCase() || '';
    const language = EXTENSION_MAP[extension] || 'unknown';

    // 2. Performance: Pre-filter rules once
    const rulesToApply = RULES.filter(r => r.language === 'all' || r.language === language).map(r => ({
        ...r,
        // Cache compiled regex if possible (or just use established string pattern)
        compiledRegex: new RegExp(r.pattern, 'i') // Assuming case insensitive default, checking flags later if needed
    }));

    const lines = content.split('\n');
    const matches: ThreatMatch[] = [];

    // 3. Safety: Limit total matches per file to prevent memory exhaustion
    const MAX_MATCHES_PER_FILE = 50;

    for (let i = 0; i < lines.length; i++) {
        if (matches.length >= MAX_MATCHES_PER_FILE) break;

        const line = lines[i];

        // 4. Safety: Skip minified/huge lines to prevent regex DoS
        if (line.length > 2000) continue;

        // 5. Optimization: Iteration
        for (const rule of rulesToApply) {
            // Note: In rules.ts, patterns should ideally be strings that are valid regexes
            // We use the pre-compiled regex here to avoid re-compiling 1000s of times
            try {
                if (rule.compiledRegex.test(line)) {
                    matches.push({
                        ruleId: rule.id,
                        severity: rule.severity,
                        line: i + 1,
                        content: line.trim().substring(0, 200), // Truncate content for UI display
                        file: fileName,
                        capability: rule.capability,
                        description: rule.description
                    });
                    // Optimization: If a line matches a critical rule, maybe we don't need to check all other rules for THIS line?
                    // For now, we continue finding all threats.
                }
            } catch (e) {
                // Ignore invalid regex issues during runtime to prevent crash
            }
        }
    }

    return matches;
};
