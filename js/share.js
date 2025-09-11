document.addEventListener('DOMContentLoaded', () => {
    'use strict';
    
    //=================================================================================
    //  SHARE MODULE
    //=================================================================================
    const ShareUtils = {
        _b64ToUrlSafe: b64 => b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        _urlSafeToB64: b64 => b64.replace(/-/g, '+').replace(/_/g, '/'),
        _arrayBufferToBase64: buffer => window.btoa(String.fromCharCode(...new Uint8Array(buffer))),
        _base64ToArrayBuffer: base64 => Uint8Array.from(window.atob(base64), c => c.charCodeAt(0)).buffer,

        // Derives a static key for encrypting/decrypting passwords in share links
        _getShareCryptoKey: async () => {
            const salt = new TextEncoder().encode('nyx-salt');
            const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(CONFIG.CONSTANTS.SHARE_KEY_MATERIAL), { name: 'PBKDF2' }, false, ['deriveKey']);
            return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        },

        // Encrypts a password for inclusion in a share link
        encryptPassword: async (password) => {
            if (!password) return null;
            const key = await ShareUtils._getShareCryptoKey();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(password));
            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(encrypted), iv.length);
            return ShareUtils._b64ToUrlSafe(ShareUtils._arrayBufferToBase64(combined.buffer));
        },

        // Decrypts a password from a share link
        decryptPassword: async (encryptedB64) => {
            if (!encryptedB64) return null;
            try {
                const key = await ShareUtils._getShareCryptoKey();
                const data = ShareUtils._base64ToArrayBuffer(ShareUtils._urlSafeToB64(encryptedB64));
                const iv = data.slice(0, 12);
                const encrypted = data.slice(12);
                const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
                return new TextDecoder().decode(decrypted);
            } catch (e) {
                console.error("Failed to decrypt password from URL", e);
                return null;
            }
        },

        // Compresses an array of URLs into a compact, URL-safe string
        compressUrls: async (urls) => {
            if (urls.length === 0) return '';
            const findCommonPrefix = (strs) => {
                if (!strs || strs.length === 0) return '';
                let prefix = strs[0];
                for (let i = 1; i < strs.length; i++) {
                    while (strs[i].indexOf(prefix) !== 0) {
                        prefix = prefix.substring(0, prefix.length - 1);
                        if (prefix === '') return '';
                    }
                }
                return prefix;
            };
            const prefix = findCommonPrefix(urls);
            const suffixes = urls.map(url => url.substring(prefix.length));
            const data = { p: prefix, u: suffixes };
            const stream = new Blob([JSON.stringify(data)], { type: 'application/json' }).stream().pipeThrough(new CompressionStream('gzip'));
            const compressed = await new Response(stream).arrayBuffer();
            return ShareUtils._b64ToUrlSafe(ShareUtils._arrayBufferToBase64(compressed));
        },

        // Decompresses a URL-safe string back into an array of URLs
        decompressUrls: async (compressedB64) => {
            if (!compressedB64) return [];
            const compressed = ShareUtils._base64ToArrayBuffer(ShareUtils._urlSafeToB64(compressedB64));
            const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'));
            const decompressed = await new Response(stream).json();
            const { p: prefix, u: suffixes } = decompressed;
            return suffixes.map(suffix => prefix + suffix);
        },
    };
    window.ShareUtils = ShareUtils;
    
    // Extend the App module with share-specific handlers
    Object.assign(App, {
        // Handles the 'Generate Link' button click in the 'Share' view
        handleGenerateShareLink: async () => {
            const urls = elements.shareUrls.value.split('\n').map(u => u.trim()).filter(Boolean);
            if (urls.length === 0) return UI.showToast('Please enter at least one URL.', 'warning');

            try {
                const password = elements.sharePassword.value;
                const baseUrl = `${window.location.origin}${window.location.pathname}`;
                const compressedUrls = await ShareUtils.compressUrls(urls);
                const encryptedPassword = await ShareUtils.encryptPassword(password);
                
                const params = new URLSearchParams();
                params.set('d', compressedUrls);
                if (encryptedPassword) params.set('pk', encryptedPassword);

                elements.shareLinkOutput.value = `${baseUrl}?${params.toString()}`;
                elements.shareLinkArea.classList.remove(CONFIG.CLASSES.hidden);
                UI.showToast('Share link generated!', 'success');
            } catch (e) {
                UI.showToast('Failed to generate link.', 'error');
                console.error("Error generating share link:", e);
            }
        },
    });

    // Encapsulated setup function for this view
    function setupShareViewEventListeners() {
        elements.generateShareLink.addEventListener('click', App.handleGenerateShareLink);
        elements.copyShareLink.addEventListener('click', () => { navigator.clipboard.writeText(elements.shareLinkOutput.value); UI.showToast('Share link copied!', 'success'); });
    }
    
    // Initialize this view
    setupShareViewEventListeners();
});