import JSZip from 'jszip';

export const fetchRepoZip = async (owner: string, repo: string, branch: string = 'main'): Promise<JSZip> => {
    console.log(`[Scanner] Attempting to fetch: ${owner}/${repo} (${branch})`);

    // Detect extension context
    const isExtension = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage;

    if (isExtension) {
        console.log("[Scanner] Using Background Script Proxy to bypass CORS");
        return new Promise((resolve, reject) => {
            chrome.runtime.sendMessage({
                type: 'FETCH_REPO',
                payload: { owner, repo, branch }
            }, async (response) => {
                if (chrome.runtime.lastError) {
                    console.error("[Scanner] chrome.runtime.lastError:", chrome.runtime.lastError);
                    return reject(new Error(chrome.runtime.lastError.message));
                }
                if (response && response.success) {
                    console.log("[Scanner] Data received from background, decoding base64...");
                    // Decode base64 to binary string
                    const binaryString = atob(response.data);
                    const len = binaryString.length;
                    const bytes = new Uint8Array(len);
                    for (let i = 0; i < len; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }

                    const zip = await JSZip.loadAsync(bytes.buffer);
                    resolve(zip);
                } else {
                    console.error("[Scanner] Background fetch error:", response?.error);
                    reject(new Error(response?.error || 'Failed to fetch repo via background.'));
                }
            });
        });
    }

    console.warn("[Scanner] Not in extension context or chrome.runtime missing. Falling back to direct fetch.");
    // Fallback for local development (will hit CORS on real GitHub URLs if not in extension)
    const url = `https://github.com/${owner}/${repo}/archive/refs/heads/${branch}.zip`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Fetch failed: ${response.statusText}`);
    const blob = await response.arrayBuffer();
    return await JSZip.loadAsync(blob);
};

export const extractFiles = async (zip: JSZip): Promise<{ path: string, content: string }[]> => {
    const files: { path: string, content: string }[] = [];

    // Iterate
    const promises: Promise<void>[] = [];

    zip.forEach((relativePath, zipEntry) => {
        if (!zipEntry.dir) {
            promises.push(
                zipEntry.async('string').then(content => {
                    // Check if binary? simple check
                    // If content has null bytes, maybe skip or mark as binary
                    // For now, we assume text for relevant extensions
                    // Filter by extensions we care about to save memory
                    const ext = relativePath.split('.').pop()?.toLowerCase();
                    if (ext && ['js', 'ts', 'jsx', 'tsx', 'py', 'go', 'java', 'c', 'cpp', 'h', 'php', 'sh', 'bash', 'ps1', 'bat', 'cmd', 'json', 'yml', 'yaml'].includes(ext)) {
                        files.push({ path: relativePath, content });
                    }
                })
            );
        }
    });

    await Promise.all(promises);
    return files;
};
