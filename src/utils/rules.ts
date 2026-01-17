import type { Rule } from '../types/scanner';

export const RULES: Rule[] = [
    // --- GENERIC / ALL ---
    {
        id: 'gen_ip_addr',
        language: 'all',
        pattern: /\b(?!127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
        severity: 'medium',
        capability: 'network_connect',
        description: 'Hardcoded public IP address. Potential C2 communication.'
    },
    {
        id: 'gen_discord_webhook',
        language: 'all',
        pattern: /https:\/\/discord(app)?\.com\/api\/webhooks\//i,
        severity: 'high',
        capability: 'info_stealing',
        description: 'Discord Webhook URL found. Common in stealers for exfiltration.'
    },
    {
        id: 'gen_telegram_bot',
        language: 'all',
        pattern: /api\.telegram\.org\/bot/i,
        severity: 'high',
        capability: 'info_stealing',
        description: 'Telegram Bot API. Common for C2 or exfiltration.'
    },
    {
        id: 'gen_pastebin',
        language: 'all',
        pattern: /(pastebin\.com|raw\.githubusercontent\.com|gist\.githubusercontent\.com)/i,
        severity: 'medium',
        capability: 'dynamic_code_loading',
        description: 'Reference to raw code hosting sites. Often used for payload downloading (Droppers).'
    },
    {
        id: 'gen_crypto_wallet',
        language: 'all',
        pattern: /(wallet\.dat|keystore|metamask|exodus|binance|coinbase)/i,
        severity: 'medium',
        capability: 'info_stealing',
        description: 'References to crypto wallets.'
    },

    // --- JAVASCRIPT / TYPESCRIPT ---
    {
        id: 'js_eval',
        language: 'javascript',
        pattern: /eval\s*\(/i,
        severity: 'high',
        capability: 'dynamic_code_loading',
        description: 'Usage of eval(). Allows arbitrary code execution.'
    },
    {
        id: 'js_child_process',
        language: 'javascript',
        pattern: /require\(['"]child_process['"]\)|child_process\.(exec|spawn|fork|execSync)/i,
        severity: 'medium',
        capability: 'command_exec',
        description: 'Executing system commands via child_process.'
    },
    {
        id: 'js_obfuscation_hex',
        language: 'javascript',
        pattern: /(\\x[0-9a-fA-F]{2}){4,}/,
        severity: 'medium',
        capability: 'obfuscation',
        description: 'Hex string obfuscation detected.'
    },
    {
        id: 'js_browser_stealer',
        language: 'javascript',
        pattern: /(localStorage|sessionStorage|indexedDB)\.getItem/i,
        severity: 'low',
        capability: 'info_stealing',
        description: 'Accessing local storage. Could be stealing tokens.'
    },
    {
        id: 'js_process_env',
        language: 'javascript',
        pattern: /process\.env/i,
        severity: 'low',
        capability: 'info_stealing',
        description: 'Accessing environment variables. Check if used to steal secrets.'
    },

    // --- PYTHON ---
    {
        id: 'py_eval_exec',
        language: 'python',
        pattern: /\b(eval|exec)\s*\(/i,
        severity: 'high',
        capability: 'dynamic_code_loading',
        description: 'Dynamic code execution via eval/exec.'
    },
    {
        id: 'py_subprocess',
        language: 'python',
        pattern: /(subprocess\.(call|Popen|run)|os\.system|os\.popen)/i,
        severity: 'medium',
        capability: 'command_exec',
        description: 'Spawning shell commands.'
    },
    {
        id: 'py_socket_bind',
        language: 'python',
        pattern: /\.bind\(\s*\(\s*['"]0\.0\.0\.0['"]/,
        severity: 'critical',
        capability: 'network_listen',
        description: 'Binding to 0.0.0.0. Evidence of a listener/backdoor.'
    },
    {
        id: 'py_reverse_shell',
        language: 'python',
        pattern: /socket\.socket|subprocess\.call.*\/bin\/sh/i,
        severity: 'high',
        capability: 'network_connect',
        description: 'Potential reverse shell code.'
    },
    {
        id: 'py_browser_steal',
        language: 'python',
        pattern: /(sqlite3\.connect.*(Login Data|Cookies|Web Data)|win32crypt\.CryptUnprotectData)/i,
        severity: 'critical',
        capability: 'info_stealing',
        description: 'Accessing browser SQLite DBs or decrypting passwords (Stealer).'
    },
    {
        id: 'py_keylogger',
        language: 'python',
        pattern: /(pynput\.keyboard|keyboard\.hook|GetAsyncKeyState)/i,
        severity: 'high',
        capability: 'info_stealing',
        description: 'Keylogging library usage detected.'
    },
    {
        id: 'py_ransom_encrypt',
        language: 'python',
        pattern: /(fernet|AES\.new|Cipher|encrypt).*\.(walk|glob)/i,
        severity: 'high',
        capability: 'file_write',
        description: 'Looping through files and encrypting them (Ransomware behavior).'
    },

    // --- POWERSHELL ---
    {
        id: 'ps_iex',
        language: 'powershell',
        pattern: /Invoke-Expression|IEX/i,
        severity: 'critical',
        capability: 'dynamic_code_loading',
        description: 'Invoke-Expression (IEX) is a hallmark of fileless malware.'
    },
    {
        id: 'ps_download_run',
        language: 'powershell',
        pattern: /(Net\.WebClient|DownloadString|DownloadFile|Invoke-WebRequest|iwr|wget|curl).*\|.*(IEX|Invoke-Expression|bash|sh)/i,
        severity: 'critical',
        capability: 'network_connect',
        description: 'Download and Execute chain in a single line.'
    },
    {
        id: 'ps_hidden',
        language: 'powershell',
        pattern: /-WindowStyle\s+Hidden/i,
        severity: 'high',
        capability: 'evasion',
        description: 'Attempting to hide the PowerShell window.'
    },
    {
        id: 'ps_amsi_bypass',
        language: 'powershell',
        pattern: /(AMSI|AmsiUtils|amsiInitFailed)/i,
        severity: 'critical',
        capability: 'evasion',
        description: 'Attempting to bypass AMSI (Anti-Malware Scan Interface).'
    },

    // --- BASH / SHELL ---
    {
        id: 'bash_curl_bash',
        language: 'bash',
        pattern: /(curl|wget|fetch)\s+.*\s+\|\s*(bash|sh|zsh)/i,
        severity: 'critical',
        capability: 'dynamic_code_loading',
        description: 'Piping web content to shell (Dropper).'
    },
    {
        id: 'bash_reverse_tcp',
        language: 'bash',
        pattern: /\/dev\/tcp\/.*\/[0-9]+/i,
        severity: 'critical',
        capability: 'network_connect',
        description: 'Bash reverse shell via /dev/tcp.'
    },
    {
        id: 'bash_persistence',
        language: 'bash',
        pattern: /(\/etc\/init\.d|\.bashrc|\.profile|\/etc\/rc\.local|cron)/i,
        severity: 'medium',
        capability: 'persistence',
        description: 'Modifying startup files for persistence.'
    },

    // --- GO ---
    {
        id: 'go_exec',
        language: 'go',
        pattern: /os\/exec\.Command/i,
        severity: 'medium',
        capability: 'command_exec',
        description: 'Executing system commands.'
    },

    // --- C/C++ ---
    {
        id: 'c_injection',
        language: 'c',
        pattern: /(VirtualAllocEx|CreateRemoteThread|WriteProcessMemory)/i,
        severity: 'critical',
        capability: 'process_inject',
        description: 'Windows API usage for Process Injection.'
    }
];
