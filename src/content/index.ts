console.log("GitHub Malware Scanner Content Script Loaded");

// Listen for messages from Popup
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === "GET_PAGE_INFO") {
        sendResponse({
            title: document.title,
            url: window.location.href
        });
    }
});
