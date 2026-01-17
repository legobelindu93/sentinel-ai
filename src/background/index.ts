// Background Service Worker
chrome.runtime.onInstalled.addListener(() => {
    console.log('GitHub Malware Scanner installed.');
});

// Listener for messages
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === 'PING') {
        sendResponse({ status: 'PONG' });
        return true;
    }

    if (message.type === 'FETCH_REPO') {
        const { owner, repo, branch } = message.payload;
        fetchRepo(owner, repo, branch)
            .then(base64 => sendResponse({ success: true, data: base64 }))
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true; // Keep channel open for async response
    }
});

async function fetchRepo(owner: string, repo: string, branch: string = 'main'): Promise<string> {
    let url = `https://github.com/${owner}/${repo}/archive/refs/heads/${branch}.zip`;

    let response = await fetch(url);
    if (!response.ok && branch === 'main') {
        url = `https://github.com/${owner}/${repo}/archive/refs/heads/master.zip`;
        response = await fetch(url);
    }

    if (!response.ok) {
        throw new Error(`Failed to fetch repository: ${response.statusText}`);
    }

    const buffer = await response.arrayBuffer();
    // Convert ArrayBuffer to Base64 string
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
