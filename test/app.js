document.addEventListener('DOMContentLoaded', () => {

    // =================================================================================
    // --- CONFIGURATION & CONSTANTS ---
    // =================================================================================
    const CONFIG = {
        CONSTANTS: {
            MAGIC: new TextEncoder().encode('NYXPKG1 '), // 8-byte package identifier
            PACKAGE_FORMAT_VERSION: 5, // v5 introduced metadata protection via HMAC signature
            SHARE_KEY_MATERIAL: 'NYX-SHARE-OBFUSCATION-KEY-V1',
        },
        SELECTORS: {
            views: {
                createView: '#create-view',
                importView: '#import-view',
                editView: '#edit-view',
                shareView: '#share-view',
            },
            buttons: {
                switchToCreate: '#switchToCreate', switchToImport: '#switchToImport', switchToEdit: '#switchToEdit', switchToShare: '#switchToShare',
                create: '#createBtn', clear: '#clearBtn', copyKey: '#copyKeyBtn',
                verifyKey: '#verifyKeyBtn', saveChanges: '#saveChangesBtn', clearEdit: '#clearEditBtn',
                unlockContent: '#unlockContentBtn', configureMetadata: '#configureMetadataBtn',
                generateShareLink: '#generateShareLinkBtn', copyShareLink: '#copyShareLinkBtn',
            },
            inputs: {
                fileInput: '#fileInput', importInput: '#importInput', editInput: '#editInput', splitSize: '#splitSize',
                masterKey: '#masterKeyInput', encryptionPassword: '#encryptionPassword',
                importPasswordInput: '#importPasswordInput', editOldPassword: '#editOldPassword', editNewPassword: '#editNewPassword',
                shareUrls: '#shareUrls', sharePassword: '#sharePassword',
            },
            zones: {
                uploadZone: '#uploadZone', importZone: '#importZone', editZone: '#editZone'
            },
            displays: {
                fileList: '#fileList', shardInfo: '#shardInfo', totalSizeInfo: '#totalSizeInfo',
                progress: '#createProgress', progressFill: '#progressFill', progressText: '#progressText',
                masterKeyArea: '#masterKeyArea', masterKeyOutput: '#masterKeyOutput', pkgInfo: '#pkgInfo',
                importPasswordPrompt: '#importPasswordPrompt',
                editEncryptionStatus: '#editEncryptionStatus', customDataContent: '#customDataContent',
                shareLinkOutput: '#shareLinkOutput',
            },
            containers: {
                download: '#downloadArea', editDownload: '#editDownloadArea',
                editForm: '#editFormContainer', editKeyVerification: '#editKeyVerification', toast: '#toastContainer',
                editEncryptionSection: '#editEncryptionSection', editOldPasswordGroup: '#editOldPasswordGroup',
                customData: '#customDataContainer', shareLinkArea: '#shareLinkArea',
            },
            forms: {
                metadata: '#metadataForm', pkgName: '#pkgName', pkgAuthor: '#pkgAuthor', pkgDescription: '#pkgDescription',
                pkgSource: '#pkgSource', pkgTags: '#pkgTags', pkgVersion: '#pkgVersion', pkgCreated: '#pkgCreated', pkgCustomData: '#pkgCustomData',
            },
            templates: { fileItem: '#file-item-template' },
        },
        CLASSES: {
            hidden: 'hidden',
            dragover: 'dragover',
            activeView: 'active-view',
            activeBtn: 'active',
        },
        SUPPORTED_PREVIEW_TYPES: {
            archive: ['application/zip', 'application/x-zip-compressed'],
        },
    };

    // =================================================================================
    // --- DOM ELEMENT CACHE ---
    // =================================================================================
    const elements = Object.values(CONFIG.SELECTORS).reduce((acc, group) => {
        for (const [key, selector] of Object.entries(group)) {
            acc[key] = document.querySelector(selector);
        }
        return acc;
    }, {});


    // =================================================================================
    // --- STATE MANAGEMENT ---
    // =================================================================================
    /**
     * Manages the application's state in a centralized, private manner.
     */
    const State = (() => {
        const _state = {
            files: [], // Files staged for creation
            isProcessing: false, // Global flag for long-running tasks
            currentImportedShards: [], // Shard data for the imported package
            currentMasterHeader: null, // Assembled header from imported shards
            activePreviewUrl: null, // Object URL for the current preview to allow revocation
            shardsForEditing: [], // Shard data for the package being edited
            isEditorUnlocked: false, // Flag indicating if the editor form is unlocked
            currentEncryptionKey: null, // CryptoKey object for decryption
            pendingFileAction: null, // Caches a file action (e.g., download) while waiting for password
            isContentUnlocked: false, // Flag indicating if encrypted content is accessible
            pendingMetadata: null, // Caches metadata from the configuration step
            isConfiguring: false, // Flag for when the editor is being used for pre-creation metadata config
        };

        return {
            getState: () => ({ ..._state }),

            setProcessing: (isProcessing) => {
                if (typeof isProcessing !== 'boolean') return;
                _state.isProcessing = isProcessing;
                UI.updateCreateViewState();
            },

            setFiles: (files) => {
                _state.files = files;
                UI.updateCreateViewState();
            },

            resetCreateView: () => {
                _state.files = [];
                _state.pendingMetadata = null;
                UI.updateCreateViewState();
                UI.clearDownloadArea();
                UI.hideMasterKey();
            },

            addFiles: (newFileObjects) => {
                const existingPaths = new Set(_state.files.map(f => f.fullPath));
                const validFiles = newFileObjects.filter(fObj => {
                    const alreadyExists = existingPaths.has(fObj.fullPath);
                    if (alreadyExists) UI.showToast(`File "${fObj.fullPath}" already added`, 'warning');
                    return !alreadyExists;
                });

                if (validFiles.length > 0) {
                    _state.files.push(...validFiles);
                    UI.showToast(`Added ${validFiles.length} file${validFiles.length === 1 ? '' : 's'}`, 'success');
                    UI.updateCreateViewState();
                }
            },

            // Direct state mutations for properties without side effects
            mut: (key, value) => {
                if (key in _state) {
                    _state[key] = value;
                }
            },
        };
    })();


    // =================================================================================
    // --- UTILITY MODULE ---
    // =================================================================================
    /**
     * Provides generic helper functions for data manipulation and cryptography.
     */
    const Utils = {
        humanSize: bytes => {
            if (bytes === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${units[i]}`;
        },
        escapeHtml: text => String(text ?? '').replace(/[&<>"']/g, match => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[match])),
        downloadBlob: (blob, filename) => {
            const url = URL.createObjectURL(blob);
            const a = Object.assign(document.createElement('a'), { href: url, download: filename, style: "display: none;" });
            document.body.appendChild(a).click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 60000);
        },
        bigIntTo8Bytes: n => {
            const buf = new ArrayBuffer(8);
            new DataView(buf).setBigUint64(0, BigInt(n), false); // Big-endian
            return new Uint8Array(buf);
        },
        readBigInt8Bytes: bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, false), // Big-endian
        computeStringSHA256: async str => {
            const buf = new TextEncoder().encode(str);
            const hashBuf = await crypto.subtle.digest('SHA-256', buf);
            return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
        },
        generateMasterKey: (length = 42) => {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            const randomValues = new Uint32Array(length);
            crypto.getRandomValues(randomValues);
            return Array.from(randomValues, val => chars[val % chars.length]).join('');
        },
        dateToLocalISO: date => {
            const tzoffset = date.getTimezoneOffset() * 60000;
            return new Date(date.getTime() - tzoffset).toISOString().slice(0, 16);
        },
        censorFilename: path => path.split('/').map(part => {
            const lastDot = part.lastIndexOf('.');
            if (lastDot <= 0) return '*'.repeat(part.length);
            const name = part.substring(0, lastDot);
            const ext = part.substring(lastDot);
            return '*'.repeat(name.length) + ext;
        }).join('/'),
        deriveKeyFromPassword: async (password, salt) => {
            const enc = new TextEncoder().encode(password);
            const keyMaterial = await crypto.subtle.importKey('raw', enc, { name: 'PBKDF2' }, false, ['deriveKey']);
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
            );
        },
        encryptBlob: async (blob, key) => {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const data = await blob.arrayBuffer();
            const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
            return { encryptedBlob: new Blob([encryptedData]), iv: Array.from(iv) };
        },
        decryptBlob: async (encryptedBlob, key, iv) => {
            const data = await encryptedBlob.arrayBuffer();
            const ivBytes = new Uint8Array(iv);
            const decryptedData = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, data);
            return new Blob([decryptedData]);
        },
        getHmacKey: async (masterKey) => {
            const keyData = new TextEncoder().encode(masterKey);
            return crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
        },
        generateHeaderSignature: async (headerObject, masterKey) => {
            const key = await Utils.getHmacKey(masterKey);
            const { headerSignature, ...signableHeader } = headerObject;
            const canonicalString = JSON.stringify(Object.keys(signableHeader).sort().reduce((obj, key) => {
                obj[key] = signableHeader[key]; return obj;
            }, {}));
            const signatureBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(canonicalString));
            return Array.from(new Uint8Array(signatureBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        },
        verifyHeaderSignature: async (headerObject, masterKey) => {
            if (!headerObject.headerSignature) {
                throw new Error("Package is not signed. Cannot verify integrity.");
            }
            const providedSignature = headerObject.headerSignature;
            const calculatedSignature = await Utils.generateHeaderSignature(headerObject, masterKey);
            if (providedSignature !== calculatedSignature) {
                throw new Error("Metadata verification failed! The package header may have been tampered with.");
            }
            return true;
        },
    };

    // =================================================================================
    // --- SHARE UTILITY MODULE ---
    // =================================================================================
    /**
     * Handles creation and parsing of sharable URLs.
     */
    const ShareUtils = {
        _b64ToUrlSafe: b64 => b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        _urlSafeToB64: b64 => b64.replace(/-/g, '+').replace(/_/g, '/'),
        _arrayBufferToBase64: buffer => window.btoa(String.fromCharCode(...new Uint8Array(buffer))),
        _base64ToArrayBuffer: base64 => Uint8Array.from(window.atob(base64), c => c.charCodeAt(0)).buffer,
        _getShareCryptoKey: async () => {
            const salt = new TextEncoder().encode('nyx-salt');
            const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(CONFIG.CONSTANTS.SHARE_KEY_MATERIAL), { name: 'PBKDF2' }, false, ['deriveKey']);
            return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        },
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
        decompressUrls: async (compressedB64) => {
            if (!compressedB64) return [];
            const compressed = ShareUtils._base64ToArrayBuffer(ShareUtils._urlSafeToB64(compressedB64));
            const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'));
            const decompressed = await new Response(stream).json();
            const { p: prefix, u: suffixes } = decompressed;
            return suffixes.map(suffix => prefix + suffix);
        },
    };

    // =================================================================================
    // --- UI MODULE (Handles all DOM manipulations) ---
    // =================================================================================
    /**
     * Manages all direct interactions with the DOM.
     */
    const UI = {
        showToast: (message, type = 'info', duration = 4000) => {
            if (!elements.toast) return;
            const toast = Object.assign(document.createElement('div'), { className: `toast ${type}`, textContent: message, role: 'status' });
            elements.toast.appendChild(toast);
            if (duration > 0) setTimeout(() => toast.remove(), duration);
            return toast;
        },
        updateProgress: (percent, text) => {
            const clampedPercent = Math.max(0, Math.min(100, percent));
            elements.progressFill.style.width = `${clampedPercent}%`;
            elements.progressFill.setAttribute('aria-valuenow', String(clampedPercent));
            if (text) elements.progressText.textContent = text;
        },
        toggleProgress: (show, text = 'Preparing...') => {
            elements.progress.classList.toggle(CONFIG.CLASSES.hidden, !show);
            if (show) UI.updateProgress(0, text);
        },
        getFileIcon: mimeType => {
            const { currentMasterHeader, isContentUnlocked } = State.getState();
            if (!mimeType) return '📄';
            if (currentMasterHeader?.encryption && !isContentUnlocked) return '🔒';
            if (mimeType.startsWith('image/')) return '🖼️';
            if (mimeType.startsWith('video/')) return '🎬';
            if (mimeType.startsWith('audio/')) return '🎵';
            if (mimeType.startsWith('text/')) return '📝';
            if (mimeType.includes('pdf')) return '📕';
            if (CONFIG.SUPPORTED_PREVIEW_TYPES.archive.includes(mimeType)) return '📦';
            return '📄';
        },
        renderFileList: () => {
            const { files } = State.getState();
            elements.fileList.innerHTML = '';
            const fragment = document.createDocumentFragment();
            files.forEach((fileObject, index) => {
                const itemTemplate = elements.fileItem.content.cloneNode(true);
                const item = itemTemplate.querySelector('.file-item');
                item.querySelector('.file-icon').textContent = UI.getFileIcon(fileObject.file.type);
                Object.assign(item.querySelector('.file-name'), { textContent: fileObject.fullPath, title: fileObject.fullPath });
                item.querySelector('.file-size').textContent = Utils.humanSize(fileObject.file.size);
                item.querySelectorAll('button').forEach(btn => btn.dataset.index = String(index));
                
                const canPreview = Importer.getPreviewerForMime(fileObject.file.type) !== Importer.previewFallback;
                if (!canPreview) item.querySelector('button[data-action="preview"]')?.classList.add(CONFIG.CLASSES.hidden);
                
                fragment.appendChild(itemTemplate);
            });
            elements.fileList.appendChild(fragment);
        },
        updateCreateViewState: () => {
            const { files, isProcessing } = State.getState();
            UI.renderFileList();
            const hasFiles = files.length > 0;
            elements.create.disabled = !hasFiles || isProcessing;
            elements.configureMetadata.disabled = !hasFiles || isProcessing;
            const totalSize = files.reduce((sum, f) => sum + f.file.size, 0);
            elements.totalSizeInfo.textContent = totalSize > 0 ? `Total: ${Utils.humanSize(totalSize)}` : '';
            const splitSizeMB = parseFloat(elements.splitSize.value);
            if (!totalSize || isNaN(splitSizeMB) || splitSizeMB <= 0) {
                elements.shardInfo.textContent = ''; return;
            }
            const splitSizeBytes = splitSizeMB * 1024 * 1024;
            elements.shardInfo.textContent = totalSize > splitSizeBytes ? `(≈ ${Math.ceil(totalSize / splitSizeBytes)} shards)` : '';
        },
        renderDownloadArea: (files, targetElement) => {
            targetElement.innerHTML = '';
            if (files.length === 0) return;

            const linksContainer = Object.assign(document.createElement('div'), { className: 'download-links-container' });

            files.forEach(file => {
                const url = URL.createObjectURL(file.blob);
                const link = Object.assign(document.createElement('a'), { href: url, download: file.filename, className: 'download-link' });
                link.innerHTML = `<strong>${Utils.escapeHtml(file.filename)}</strong> <small>(${Utils.humanSize(file.blob.size)})</small>`;
                linksContainer.appendChild(link);
                setTimeout(() => URL.revokeObjectURL(url), 300000); // Clean up URLs after 5 minutes
            });
            
            targetElement.appendChild(linksContainer);

            if (files.length > 1) {
                const allContainer = document.createElement('div');
                const button = Object.assign(document.createElement('button'), { className: 'btn btn-primary', innerHTML: `💾 Download All as .zip` });
                button.onclick = async () => {
                    if (State.getState().isProcessing) return;
                    State.setProcessing(true);
                    UI.showToast('Zipping files...', 'info');
                    try {
                        const zip = new JSZip();
                        files.forEach(f => zip.file(f.filename, f.blob));
                        const zipBlob = await zip.generateAsync({ type: "blob" });
                        Utils.downloadBlob(zipBlob, `package-shards.zip`);
                        UI.showToast('ZIP archive created!', 'success');
                    } catch (e) { UI.showToast(`Failed to create zip: ${e.message}`, 'error'); console.error(e); }
                    finally { State.setProcessing(false); }
                };
                allContainer.appendChild(button);
                targetElement.prepend(allContainer);
            }
        },
        showMasterKey: (masterKey) => {
            elements.masterKeyOutput.value = masterKey;
            elements.masterKeyArea.classList.remove(CONFIG.CLASSES.hidden);
        },
        hideMasterKey: () => elements.masterKeyArea.classList.add(CONFIG.CLASSES.hidden),
        clearDownloadArea: () => elements.download.innerHTML = '',
    };


    // =================================================================================
    // --- PACKER MODULE (File Creation Logic) ---
    // =================================================================================
    /**
     * Handles the logic for building .nyx packages from source files.
     */
    const Packer = {
        buildBlob: async (headerObj, payloadBlobs, baseName, masterKey = null) => {
            let finalHeader = { ...headerObj };
            if (masterKey) {
                finalHeader.headerSignature = await Utils.generateHeaderSignature(finalHeader, masterKey);
            }
            const headerBytes = new TextEncoder().encode(JSON.stringify(finalHeader));
            const headerLenBuf = Utils.bigIntTo8Bytes(headerBytes.length);
            const blob = new Blob([CONFIG.CONSTANTS.MAGIC, headerLenBuf, headerBytes, ...payloadBlobs], { type: 'application/octet-stream' });
            const filename = `${baseName}-${new Date().toISOString().replace(/[:.]/g, '-')}.nyx`;
            return { blob, filename };
        },
        buildFromPayloads: async (baseHeader, finalPayloads, splitSizeBytes, masterKey = null) => {
            const totalPayloadSize = finalPayloads.reduce((sum, blob) => sum + blob.size, 0);
            if (splitSizeBytes > 0 && totalPayloadSize > splitSizeBytes) {
                return Packer.buildSplitPackage(baseHeader, finalPayloads, splitSizeBytes, masterKey);
            }
            return Packer.buildSinglePackage(baseHeader, finalPayloads, masterKey);
        },
        buildSinglePackage: async (baseHeader, payloads, masterKey = null) => {
            UI.updateProgress(90, 'Building package header...');
            let offset = 0;
            const finalEntriesWithOffset = baseHeader.files.map(e => ({ ...e, offset: (offset += e.length) - e.length }));
            const headerObj = { ...baseHeader, files: finalEntriesWithOffset, totalSize: offset };
            const builtPackage = await Packer.buildBlob(headerObj, payloads, 'package', masterKey);
            UI.updateProgress(100, 'Finalizing...');
            return [builtPackage];
        },
        buildSplitPackage: async (baseHeader, payloads, splitSizeBytes, masterKey = null) => {
            const shardData = [];
            const packageId = `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
            let shardNum = 1;
            let currentShard = { payload: [], entries: [], size: 0 };
            const totalPayloadSize = payloads.reduce((sum, p) => sum + p.size, 0);
            const totalShardsEstimate = Math.max(1, Math.ceil(totalPayloadSize / splitSizeBytes));

            const finalizeCurrentShard = async () => {
                if (currentShard.payload.length === 0) return;
                const headerObj = { ...baseHeader, files: currentShard.entries, totalSize: currentShard.size, splitInfo: { id: packageId, shard: shardNum, total: totalShardsEstimate } };
                shardData.push(await Packer.buildBlob(headerObj, currentShard.payload, `package-shard${shardNum}`, masterKey));
                shardNum++;
                currentShard = { payload: [], entries: [], size: 0 };
            };

            for (let i = 0; i < payloads.length; i++) {
                const fileBlob = payloads[i];
                const fileEntryTemplate = { ...baseHeader.files[i] };
                let fileBytesProcessed = 0;

                while (fileBytesProcessed < fileBlob.size) {
                    UI.updateProgress(80 + (shardNum / totalShardsEstimate) * 20, `Building shard ${shardNum}/${totalShardsEstimate}...`);
                    if (currentShard.size >= splitSizeBytes) await finalizeCurrentShard();

                    const spaceInShard = splitSizeBytes - currentShard.size;
                    const bytesToProcess = Math.min(fileBlob.size - fileBytesProcessed, spaceInShard);

                    currentShard.payload.push(fileBlob.slice(fileBytesProcessed, fileBytesProcessed + bytesToProcess));
                    currentShard.entries.push({ ...fileEntryTemplate, length: bytesToProcess, offset: currentShard.size, totalSize: fileBlob.size });
                    currentShard.size += bytesToProcess;
                    fileBytesProcessed += bytesToProcess;
                }
            }
            await finalizeCurrentShard();
            UI.showToast(`Package successfully split into ${shardNum - 1} shards.`, 'success');
            return shardData;
        },
        createPackage: async (files, password, splitSizeMB, metadata) => {
            const masterKey = Utils.generateMasterKey();
            const keyHash = await Utils.computeStringSHA256(masterKey);
            const createFileEntries = () => files.map(({ file, fullPath }) => ({ name: fullPath, mime: file.type || 'application/octet-stream', length: file.size, lastModified: file.lastModified ?? Date.now() }));
            
            const baseHeader = { 
                ...metadata,
                formatVersion: CONFIG.CONSTANTS.PACKAGE_FORMAT_VERSION, 
                created: metadata.created || Date.now(), 
                keyHash, 
                files: createFileEntries()
            };

            const splitSizeBytes = !isNaN(splitSizeMB) && splitSizeMB > 0 ? splitSizeMB * 1024 * 1024 : 0;
            const finalPayloads = [];

            if (password) {
                UI.updateProgress(10, "Deriving encryption key...");
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const encryptionKey = await Utils.deriveKeyFromPassword(password, salt);
                baseHeader.encryption = { salt: Array.from(salt) };

                for (let i = 0; i < files.length; i++) {
                    UI.updateProgress(10 + (i / files.length * 70), `Encrypting ${files[i].fullPath}...`);
                    const { encryptedBlob, iv } = await Utils.encryptBlob(files[i].file, encryptionKey);
                    finalPayloads.push(encryptedBlob);
                    baseHeader.files[i].iv = iv;
                    baseHeader.files[i].length = encryptedBlob.size;
                }
            } else {
                finalPayloads.push(...files.map(f => f.file));
            }
            
            const packages = await Packer.buildFromPayloads(baseHeader, finalPayloads, splitSizeBytes, masterKey);
            return { packages, masterKey };
        },
    };


    // =================================================================================
    // --- IMPORTER MODULE (File Extraction Logic) ---
    // =================================================================================
    /**
     * Handles parsing .nyx packages and extracting file content.
     */
    const Importer = {
        readPackageHeader: async (packageFile) => {
            if (!packageFile.name.toLowerCase().endsWith('.nyx')) throw new Error(`Invalid file type: ${packageFile.name}`);
            const headerBuffer = await packageFile.slice(0, 16).arrayBuffer();
            const headerBytes = new Uint8Array(headerBuffer);
            if (new TextDecoder().decode(headerBytes.slice(0, 8)) !== new TextDecoder().decode(CONFIG.CONSTANTS.MAGIC)) throw new Error('Invalid package file (bad magic header)');
            const headerLength = Number(Utils.readBigInt8Bytes(headerBytes.slice(8, 16)));
            if (headerLength > packageFile.size) throw new Error('Corrupted header (invalid length)');
            const headerEnd = 16 + headerLength;
            const headerJsonBuffer = await packageFile.slice(16, headerEnd).arrayBuffer();
            try {
                const header = JSON.parse(new TextDecoder().decode(headerJsonBuffer));
                return { header, payloadStart: headerEnd, packageFile };
            } catch (e) { throw new Error('Corrupted header (possible unauthorized metadata tampering)'); }
        },
        processHeaders: (headers) => {
            if (headers.length === 0) throw new Error("No valid package shards found.");
            const firstHeader = headers[0].header;
            if (!firstHeader.splitInfo) {
                if (headers.length > 1) throw new Error("Cannot import multiple non-split packages at once.");
                return { masterHeader: firstHeader, sortedShards: [headers[0]] };
            }
            const { id, total } = firstHeader.splitInfo;
            const relevantShards = headers.filter(h => h.header.splitInfo?.id === id);
            
            if (relevantShards.length !== total) {
                throw new Error(`Incomplete package. Expected ${total} shards but only found ${relevantShards.length}.`);
            }
            if (new Set(relevantShards.map(s => s.header.splitInfo.shard)).size < relevantShards.length) {
                throw new Error("Duplicate shards detected. Please load a valid, complete set of shards.");
            }

            const sortedShards = relevantShards.sort((a, b) => a.header.splitInfo.shard - b.header.splitInfo.shard);
            const masterFilesMap = new Map();
            sortedShards.forEach(shard => shard.header.files.forEach(chunk => {
                if (!masterFilesMap.has(chunk.name)) masterFilesMap.set(chunk.name, { ...chunk, length: chunk.totalSize, chunks: [] });
                masterFilesMap.get(chunk.name).chunks.push({ shard: shard.header.splitInfo.shard, offset: chunk.offset, length: chunk.length });
            }));
            const masterHeader = { ...sortedShards[0].header, files: Array.from(masterFilesMap.values()) };
            delete masterHeader.splitInfo;
            return { masterHeader, sortedShards };
        },
        _extractRawFileBlob: async (fileEntry, sourceShards) => {
             if (!fileEntry.chunks || fileEntry.chunks.length === 0) {
                const shard = sourceShards[0];
                return shard.packageFile.slice(shard.payloadStart + fileEntry.offset, shard.payloadStart + fileEntry.offset + fileEntry.length);
            }
            const chunkBlobs = await Promise.all(fileEntry.chunks.map(async chunk => {
                const shard = sourceShards.find(s => s.header.splitInfo.shard === chunk.shard);
                if (!shard) throw new Error(`Could not find shard #${chunk.shard} for file "${fileEntry.name}"`);
                const blobSlice = shard.packageFile.slice(shard.payloadStart + chunk.offset, shard.payloadStart + chunk.offset + chunk.length);
                return blobSlice.arrayBuffer();
            }));
            return new Blob(chunkBlobs);
        },
        extractFileBlob: async (fileEntry) => {
            const { currentImportedShards, currentMasterHeader, currentEncryptionKey } = State.getState();
            const rawBlob = await Importer._extractRawFileBlob(fileEntry, currentImportedShards);
            if (currentMasterHeader.encryption) {
                if (!currentEncryptionKey) throw new Error("Encryption key not available.");
                try {
                    UI.showToast(`Decrypting ${fileEntry.name}...`, 'info', 1500);
                    return await Utils.decryptBlob(rawBlob, currentEncryptionKey, fileEntry.iv);
                } catch (e) {
                    console.error("Decryption failed:", e);
                    throw new Error("Decryption failed. The password may be incorrect.");
                }
            }
            return new Blob([await rawBlob.arrayBuffer()], { type: fileEntry.mime });
        },
        displayPackageInfo: (header, totalSize) => {
            const { currentImportedShards } = State.getState();
            elements.pkgInfo.innerHTML = '';
            const details = {
                'Author': header.author, 'Files': header.files.length, 'Total Size': Utils.humanSize(totalSize),
                'Created': new Date(header.created || 0).toLocaleString(),
                'Encryption': header.encryption ? 'AES-GCM' : 'None',
                'Content Version': header.version ?? 1,
                'Package Format Version': header.formatVersion ?? 1,
            };
            const detailsHtml = Object.entries(details).filter(([, v]) => v).map(([k, v]) => `<div><strong>${k}:</strong> ${Utils.escapeHtml(v)}</div>`).join('');
            const descriptionHtml = header.description ? `<p class="package-description">${Utils.escapeHtml(header.description)}</p>` : '';
            const tagsHtml = header.tags?.length ? `<div class="package-tags">${header.tags.map(tag => `<span class="tag">${Utils.escapeHtml(tag)}</span>`).join('')}</div>` : '';
            const sourcesHtml = header.source ? `
                <div class="package-sources">
                    <strong>Source${header.source.includes(',') ? 's' : ''}:</strong>
                    <ul>
                        ${header.source.split(',').map(s => s.trim()).filter(Boolean).map(source => {
                            try {
                                if (!source.startsWith('http')) throw new Error('Not a full URL');
                                const url = new URL(source);
                                return `<li><a href="${Utils.escapeHtml(url.href)}" target="_blank" rel="noopener noreferrer">${Utils.escapeHtml(source)}</a></li>`;
                            } catch (_) {
                                return `<li>${Utils.escapeHtml(source)}</li>`;
                            }
                        }).join('')}
                    </ul>
                </div>` : '';

            const shardInfo = currentImportedShards.length > 1 ? `<div><strong>Shards:</strong> ${currentImportedShards.length}</div>` : '';
            const customDataButton = header.customData ? `<button class="btn btn-secondary btn-small ${header.encryption ? 'hidden' : ''}" data-action="view-custom-data">View Custom Data</button>` : '';

            const summary = document.createElement('div');
            summary.className = 'package-summary';
            summary.innerHTML = `
                <h3><span class="pkg-name">${Utils.escapeHtml(header.packageName) || 'Untitled Package'}</span></h3>
                ${descriptionHtml}${tagsHtml}${sourcesHtml}
                <div class="package-details-grid">${detailsHtml}${shardInfo}</div>
                <div class="view-actions">
                    <button class="btn btn-primary" data-action="save-all-zip">💾 Download All as .zip</button>
                    ${customDataButton}
                </div>`;
            
            elements.pkgInfo.appendChild(summary);
            
            if(header.customData) elements.customDataContent.textContent = JSON.stringify(header.customData, null, 2);
        },
        createFileActionsList: (files) => {
            const listContainer = Object.assign(document.createElement('div'), { className: 'file-list' });
            const rootEntries = new Map();
            files.forEach((fileEntry, index) => {
                const pathParts = fileEntry.name.split('/');
                const topLevelName = pathParts[0];
                if (pathParts.length > 1) {
                    if (!rootEntries.has(topLevelName)) rootEntries.set(topLevelName, { type: 'folder', files: [] });
                    rootEntries.get(topLevelName).files.push(fileEntry);
                } else {
                    rootEntries.set(topLevelName, { type: 'file', fileEntry, originalIndex: index });
                }
            });
            rootEntries.forEach((entry, name) => {
                const item = entry.type === 'folder'
                    ? Importer.createPackageFolderItem(name, entry.files)
                    : Importer.createPackageFileItem(entry.fileEntry, entry.originalIndex);
                listContainer.appendChild(item);
            });
            elements.pkgInfo.appendChild(listContainer);
        },
        createPackageFolderItem: (folderName, folderFiles) => {
            const { currentMasterHeader, isContentUnlocked } = State.getState();
            const item = document.createElement('div');
            item.className = 'file-item';
            const totalSize = folderFiles.reduce((sum, f) => sum + f.length, 0);
            const fileNamesJson = Utils.escapeHtml(JSON.stringify(folderFiles.map(f => f.name)));
            const isLocked = currentMasterHeader?.encryption && !isContentUnlocked;
            const icon = isLocked ? '🔒' : '📁';
            const displayName = isLocked ? Utils.censorFilename(folderName) : Utils.escapeHtml(folderName);

            item.innerHTML = `<div class="file-icon">${icon}</div>
                <div class="file-meta"><div class="file-name" title="${displayName}">${displayName}</div><div class="file-size">${Utils.humanSize(totalSize)} (${folderFiles.length} items)</div></div>
                <div class="file-actions"><button class="btn btn-small btn-primary" data-action="save-folder" data-folder-name="${Utils.escapeHtml(folderName)}" data-files-json='${fileNamesJson}'>💾 ZIP</button></div>`;
            return item;
        },
        createPackageFileItem: (fileEntry, index) => {
            const { currentMasterHeader, isContentUnlocked } = State.getState();
            const item = document.createElement('div');
            item.className = 'file-item';
            const canPreview = Importer.getPreviewerForMime(fileEntry.mime) !== Importer.previewFallback;
            const isLocked = currentMasterHeader?.encryption && !isContentUnlocked;
            const displayName = isLocked ? Utils.censorFilename(fileEntry.name) : Utils.escapeHtml(fileEntry.name);
            
            item.innerHTML = `<div class="file-icon">${UI.getFileIcon(fileEntry.mime)}</div>
                <div class="file-meta"><div class="file-name" title="${displayName}">${displayName}</div><div class="file-size">${Utils.humanSize(fileEntry.length)} - <em>${Utils.escapeHtml(fileEntry.mime) || 'unknown'}</em></div></div>
                <div class="file-actions">
                    ${canPreview ? `<button class="btn btn-small btn-secondary" data-action="preview" data-index="${index}">👁️ Preview</button>` : ''}
                    <button class="btn btn-small btn-primary" data-action="save" data-index="${index}">💾 Save</button>
                </div>`;
            return item;
        },
        refreshFileListView: () => {
            const { currentMasterHeader } = State.getState();
            elements.pkgInfo.querySelector('.file-list')?.remove();
            if (currentMasterHeader) {
                Importer.createFileActionsList(currentMasterHeader.files);
            }
        },
        displayPreview: async (blob, mimeType, targetFileItem) => {
            const { activePreviewUrl } = State.getState();
            if (activePreviewUrl) { URL.revokeObjectURL(activePreviewUrl); State.mut('activePreviewUrl', null); }
            
            const container = Object.assign(document.createElement('div'), { className: 'inline-preview-container' });

            const closeBtn = Object.assign(document.createElement('button'), {
                className: 'btn btn-small btn-danger inline-preview-close-btn', innerHTML: `&times;`,
                title: 'Close Preview', 'aria-label': 'Close Preview',
            });
            closeBtn.onclick = () => container.remove();

            const wrapper = Object.assign(document.createElement('div'), { className: 'preview-wrapper' });
            container.append(closeBtn, wrapper);

            const previewer = Importer.getPreviewerForMime(mimeType);
            await previewer(blob, wrapper);
            
            targetFileItem.after(container);
        },
        getPreviewerForMime: mime => {
            if (!mime) return Importer.previewFallback;
            if (CONFIG.SUPPORTED_PREVIEW_TYPES.archive.includes(mime)) return Importer.previewArchive;
            if (mime.startsWith('image/')) return Importer.previewMedia('img');
            if (mime.startsWith('video/')) return Importer.previewMedia('video');
            if (mime.startsWith('audio/')) return Importer.previewMedia('audio');
            if (mime.includes('svg')) return Importer.previewMedia('img');
            if (mime.startsWith('text/') || ['application/json', 'application/xml', 'application/javascript'].includes(mime)) return Importer.previewText;
            return Importer.previewFallback;
        },
        previewArchive: async (blob, wrapper) => {
            try {
                const zip = await JSZip.loadAsync(blob);
                wrapper.innerHTML = `<div class="zip-preview-list"><ul>${Object.values(zip.files).map(f => `<li class="${f.dir ? 'is-dir' : ''}">${Utils.escapeHtml(f.name)}</li>`).join('')}</ul></div>`;
            } catch (e) { Importer.previewFallback(blob, wrapper, "Could not read archive file."); }
        },
        previewMedia: type => async (blob, wrapper) => {
            const url = URL.createObjectURL(blob);
            State.mut('activePreviewUrl', url);
            const el = Object.assign(document.createElement(type), { src: url });
            if (type !== 'img') el.controls = true;
            wrapper.appendChild(el);
        },
        previewText: async (blob, wrapper) => {
            const textContent = await blob.text();
            const pre = Object.assign(document.createElement('pre'), { className: 'hljs' });
            const code = document.createElement('code');
            code.textContent = textContent;
            pre.appendChild(code);
            wrapper.appendChild(pre);

            if (typeof hljs !== 'undefined') {
                try { hljs.highlightElement(code); }
                catch(e) { console.warn('highlight.js failed', e); }
            }
        },
        previewFallback: (_, wrapper, message = "Preview not available for this file type.") => {
            wrapper.innerHTML = `<p>${message}</p>`;
        },
    };


    // =================================================================================
    // --- EDITOR MODULE (Metadata Editing Logic) ---
    // =================================================================================
    /**
     * Handles the business logic for the package editing view.
     */
    const Editor = {
        unlockForm: (header) => {
            State.mut('isEditorUnlocked', true);
            elements.editKeyVerification.classList.add(CONFIG.CLASSES.hidden);
            elements.editForm.dataset.locked = "false";
            Editor.displayMetadataForm(header);
        },
        displayMetadataForm: (header) => {
            elements.metadata.reset();
            elements.pkgName.value = header.packageName ?? '';
            elements.pkgAuthor.value = header.author ?? '';
            elements.pkgDescription.value = header.description ?? '';
            elements.pkgSource.value = header.source ?? '';
            elements.pkgTags.value = (header.tags ?? []).join(', ');
            elements.pkgVersion.value = header.version ?? 1;
            elements.pkgCreated.value = Utils.dateToLocalISO(new Date(header.created ?? Date.now()));
            elements.pkgCustomData.value = header.customData ? JSON.stringify(header.customData, null, 2) : '';

            elements.editEncryptionSection.classList.remove(CONFIG.CLASSES.hidden);
            if (header.encryption) {
                elements.editEncryptionStatus.textContent = 'Content is encrypted. Provide old password only to change/remove it.';
                elements.editOldPasswordGroup.classList.remove(CONFIG.CLASSES.hidden);
            } else {
                elements.editEncryptionStatus.textContent = 'Content is not encrypted. Provide a new password to add encryption.';
                elements.editOldPasswordGroup.classList.add(CONFIG.CLASSES.hidden);
            }
            elements.editOldPassword.value = '';
            elements.editNewPassword.value = '';
        },
        clear: () => {
            if (State.getState().isConfiguring) {
                App.returnToCreateView();
                return;
            }
            State.mut('shardsForEditing', []);
            State.mut('currentMasterHeader', null);
            State.mut('isEditorUnlocked', false);
            elements.metadata.reset();
            elements.editForm.classList.add(CONFIG.CLASSES.hidden);
            elements.editKeyVerification.classList.add(CONFIG.CLASSES.hidden);
            elements.editDownload.innerHTML = '';
            if (elements.editInput) elements.editInput.value = '';
            UI.showToast('Editor cleared.', 'info');
        },
        _getNewMetadataFromForm: () => {
            let customData = null;
            const customDataValue = elements.pkgCustomData.value.trim();
            if (customDataValue) {
               try { customData = JSON.parse(customDataValue); } 
               catch (e) { throw new Error("Custom JSON data is invalid."); }
            }
            return {
                packageName: elements.pkgName.value.trim(), author: elements.pkgAuthor.value.trim(), description: elements.pkgDescription.value.trim(),
                source: elements.pkgSource.value.trim(), tags: elements.pkgTags.value.split(',').map(t => t.trim()).filter(Boolean),
                version: parseInt(elements.pkgVersion.value, 10) || 1, 
                created: new Date(elements.pkgCreated.value).getTime() || Date.now(), customData
            };
        },
        _updatePackageMetadataOnly: async (newGlobalMetadata, masterKey) => {
            UI.updateProgress(50, "Applying new metadata...");
            const { shardsForEditing, currentMasterHeader } = State.getState();
            
            const baseHeader = { ...currentMasterHeader, ...newGlobalMetadata };
            baseHeader.keyHash = await Utils.computeStringSHA256(masterKey);

            if (shardsForEditing.length > 1) {
                const payloads = await Promise.all(currentMasterHeader.files.map(file => Importer._extractRawFileBlob(file, shardsForEditing)));
                const originalTotalSize = shardsForEditing.reduce((sum, s) => sum + s.packageFile.size, 0);
                const originalSplitSize = originalTotalSize / shardsForEditing.length;
                return Packer.buildFromPayloads(baseHeader, payloads, originalSplitSize, masterKey);
            } else {
                 const shard = shardsForEditing[0];
                 const payload = shard.packageFile.slice(shard.payloadStart);
                 const baseName = shard.packageFile.name.replace(/\.nyx$/, '');
                 const newPackage = await Packer.buildBlob(baseHeader, [payload], `${baseName}-edited`, masterKey);
                 return [newPackage];
            }
        },
        _rebuildPackageWithEncryptionChanges: async (newGlobalMetadata, oldPassword, newPassword, masterKey) => {
            const { currentMasterHeader, shardsForEditing } = State.getState();
            const wasEncrypted = !!currentMasterHeader.encryption;
            if (wasEncrypted && !oldPassword) throw new Error("Old password is required to change or remove encryption.");
            
            let oldKey = null;
            if (wasEncrypted) {
                UI.updateProgress(5, "Verifying old password...");
                oldKey = await Utils.deriveKeyFromPassword(oldPassword, new Uint8Array(currentMasterHeader.encryption.salt));
            }
            
            const newBaseHeader = { ...currentMasterHeader, ...newGlobalMetadata };
            newBaseHeader.keyHash = await Utils.computeStringSHA256(masterKey);
            let newKey = null;
            if (newPassword) {
                UI.updateProgress(10, "Deriving new encryption key...");
                const newSalt = crypto.getRandomValues(new Uint8Array(16));
                newKey = await Utils.deriveKeyFromPassword(newPassword, newSalt);
                newBaseHeader.encryption = { salt: Array.from(newSalt) };
            } else {
                delete newBaseHeader.encryption;
            }

            const finalPayloads = [];
            const newFileEntries = [];
            for (let i = 0; i < currentMasterHeader.files.length; i++) {
                const fileEntry = currentMasterHeader.files[i];
                UI.updateProgress(15 + (i / currentMasterHeader.files.length) * 65, `Processing file ${i + 1}...`);
                let currentBlob = await Importer._extractRawFileBlob(fileEntry, shardsForEditing);
                if (wasEncrypted) {
                    try { currentBlob = await Utils.decryptBlob(currentBlob, oldKey, fileEntry.iv); }
                    catch(e) { throw new Error(`Decryption failed for ${fileEntry.name}. Incorrect old password?`); }
                }
                
                const newEntry = { ...fileEntry };
                delete newEntry.chunks; delete newEntry.offset;
                if (newPassword) {
                    const { encryptedBlob, iv } = await Utils.encryptBlob(currentBlob, newKey);
                    finalPayloads.push(encryptedBlob);
                    newEntry.iv = iv;
                    newEntry.length = encryptedBlob.size;
                } else {
                    finalPayloads.push(currentBlob);
                    delete newEntry.iv;
                    newEntry.length = currentBlob.size;
                }
                newFileEntries.push(newEntry);
            }
            
            newBaseHeader.files = newFileEntries;
            const originalTotalSize = shardsForEditing.reduce((sum, s) => sum + s.packageFile.size, 0);
            const originalSplitSize = shardsForEditing.length > 1 ? originalTotalSize / shardsForEditing.length : 0;
            return Packer.buildFromPayloads(newBaseHeader, finalPayloads, originalSplitSize, masterKey);
        },
    };


    // =================================================================================
    // --- APP CONTROLLER & EVENT HANDLER ---
    // =================================================================================
    /**
     * Main application controller. Initializes the app, manages views,
     * and orchestrates all modules via event handlers.
     */
    const App = {
        init() {
            console.log("Nyx Packer App Initializing...");
            App.setupEventListeners();
            App.setupDragAndDrop();
            App.loadShardsFromUrl();
            UI.updateCreateViewState();
            UI.showToast('Application ready!', 'success');
        },
        loadShardsFromUrl: async () => {
            const params = new URLSearchParams(window.location.search);
            let shardUrls = [];
            let password = null;

            if (params.has('d')) { // New compressed/encoded format
                try {
                    shardUrls = await ShareUtils.decompressUrls(params.get('d'));
                    if (params.has('pk')) password = await ShareUtils.decryptPassword(params.get('pk'));
                } catch(e) { UI.showToast('Could not parse share link.', 'error'); console.error("Share link parsing failed:", e); return; }
            } else if (params.has('shards_b64')) { // Old b64 format for backward compatibility
                try {
                    shardUrls = atob(params.get('shards_b64')).split('\n').map(u => u.trim()).filter(Boolean);
                    password = params.get('password');
                } catch (e) { UI.showToast('Could not decode share link.', 'error'); return; }
            } else { // Direct shard links
                 shardUrls = params.getAll('shard');
                 password = params.get('password');
            }

            if (shardUrls.length === 0) return;

            App.switchToView('import');
            const importToast = UI.showToast(`Starting import of ${shardUrls.length} shard(s)...`, 'info', 0); // Persistent toast

            try {
                const files = await Promise.all(shardUrls.map(async (url, i) => {
                    importToast.textContent = `Fetching shard ${i + 1}/${shardUrls.length}...`;
                    if (!url.startsWith('http')) throw new Error(`Invalid URL: ${url.slice(0, 30)}...`);
                    const res = await fetch(url);
                    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.statusText}`);
                    const blob = await res.blob();
                    const filename = new URL(url).pathname.split('/').pop() || 'shard.nyx';
                    return new File([blob], filename, { type: 'application/octet-stream' });
                }));

                importToast.textContent = `Processing ${files.length} shard(s)...`;
                await App.handleImport(files);

                if (password && State.getState().currentMasterHeader?.encryption) {
                    UI.showToast('Password found in URL, attempting to unlock...', 'info');
                    elements.importPasswordInput.value = password;
                    setTimeout(App.handleUnlockContent, 100);
                }
            } catch (e) {
                UI.showToast(`Error loading from URL: ${e.message}`, 'error');
                console.error(e);
            } finally {
                importToast?.remove();
                history.replaceState(null, '', window.location.pathname);
            }
        },
        switchToView: (viewName) => {
            console.info(`Switching to view: ${viewName}`);
            const { isConfiguring } = State.getState();
            const currentView = document.querySelector(`.${CONFIG.CLASSES.activeView}`);
            if (currentView && currentView.id === 'edit-view' && isConfiguring && viewName !== 'edit') {
                 App.returnToCreateView(false); // don't switch view again
            }

            Object.values(CONFIG.SELECTORS.views).forEach(selector => document.querySelector(selector)?.classList.remove(CONFIG.CLASSES.activeView));
            const viewKey = `${viewName}View`;
            elements[viewKey]?.classList.add(CONFIG.CLASSES.activeView);
            
            const switcherButtons = document.querySelectorAll('.switcher-btn');
            switcherButtons.forEach(btn => {
                const isActive = btn.id === `switchTo${viewName.charAt(0).toUpperCase() + viewName.slice(1)}`;
                btn.classList.toggle(CONFIG.CLASSES.activeBtn, isActive);
                btn.setAttribute('aria-pressed', isActive);
            });
        },
        traverseFileTree: async (entry) => {
            const files = [];
            const processEntry = async (e) => {
                if (e.isFile) {
                    const file = await new Promise((res, rej) => e.file(res, rej));
                    files.push({ file, fullPath: e.fullPath.substring(1) });
                } else if (e.isDirectory) {
                    const reader = e.createReader();
                    let entries;
                    do {
                        entries = await new Promise((res, rej) => reader.readEntries(res, rej));
                        await Promise.all(entries.map(processEntry));
                    } while (entries.length > 0);
                }
            };
            if (entry) await processEntry(entry);
            return files;
        },
        createZipFromEntries: async (fileEntries, zipName) => {
            if (State.getState().isProcessing) return;
            State.setProcessing(true);
            try {
                const { currentMasterHeader, isContentUnlocked } = State.getState();
                if (currentMasterHeader.encryption && !isContentUnlocked) {
                    UI.showToast('Please unlock the package content first.', 'warning');
                    elements.importPasswordPrompt.classList.remove(CONFIG.CLASSES.hidden);
                    return;
                }
                const zip = new JSZip();
                for (const fileEntry of fileEntries) {
                    zip.file(fileEntry.name, await Importer.extractFileBlob(fileEntry));
                }
                const zipBlob = await zip.generateAsync({ type: "blob" });
                Utils.downloadBlob(zipBlob, zipName);
            } catch (e) { UI.showToast(`Failed to create zip: ${e.message}`, 'error'); console.error(e); }
            finally { State.setProcessing(false); }
        },
        
        // --- Event Handler Logic ---
        handleCreate: async () => {
            const { files, pendingMetadata } = State.getState();
            if (files.length === 0) return UI.showToast('Please add at least one file', 'warning');
            if (State.getState().isProcessing) return;

            State.setProcessing(true);
            UI.clearDownloadArea();
            UI.hideMasterKey();
            UI.toggleProgress(true, 'Preparing package...');

            try {
                const password = elements.encryptionPassword.value;
                const splitSizeMB = parseFloat(elements.splitSize.value);
                const metadata = pendingMetadata || {};
                
                const { packages, masterKey } = await Packer.createPackage(files, password, splitSizeMB, metadata);

                UI.renderDownloadArea(packages, elements.download);
                UI.showMasterKey(masterKey);
                UI.showToast('Package created successfully!', 'success');
            } catch (e) {
                UI.showToast(`Package creation failed: ${e.message}`, 'error');
                console.error(e);
            } finally {
                State.setProcessing(false);
                State.mut('pendingMetadata', null);
                elements.encryptionPassword.value = '';
                setTimeout(() => UI.toggleProgress(false), 1000);
            }
        },
        handleImport: async (packageFiles) => {
            if (!packageFiles || packageFiles.length === 0) return;
            elements.pkgInfo.innerHTML = '';
            elements.importPasswordPrompt.classList.add(CONFIG.CLASSES.hidden);
            elements.customData.classList.add(CONFIG.CLASSES.hidden);
            State.mut('currentEncryptionKey', null);
            State.mut('isContentUnlocked', false);
            document.querySelector('.inline-preview-container')?.remove();

            const importToast = UI.showToast(`Processing ${packageFiles.length} shard(s)...`, 'info', 0);
            try {
                const headers = await Promise.all([...packageFiles].map(Importer.readPackageHeader));
                const { masterHeader, sortedShards } = Importer.processHeaders(headers);
                State.mut('currentMasterHeader', masterHeader);
                State.mut('currentImportedShards', sortedShards);
                const totalSize = sortedShards.reduce((s, sh) => s + sh.packageFile.size, 0);
                
                Importer.displayPackageInfo(masterHeader, totalSize);
                Importer.createFileActionsList(masterHeader.files);
                
                if (masterHeader.encryption) {
                    elements.pkgInfo.after(elements.importPasswordPrompt);
                    elements.importPasswordPrompt.classList.remove(CONFIG.CLASSES.hidden);
                    UI.showToast('Package is encrypted. Enter password to access files.', 'info');
                }
                
                UI.showToast(`Package loaded: ${masterHeader.files.length} files`, 'success');
            } catch (e) {
                UI.showToast(`Import failed: ${e.message}`, 'error');
                console.error(e);
            } finally {
                importToast?.remove();
            }
        },
        handleUnlockContent: async () => {
            const password = elements.importPasswordInput.value;
            const { currentMasterHeader } = State.getState();
            if (!password || !currentMasterHeader?.encryption) return;

            UI.showToast('Verifying password...', 'info');
            try {
                const salt = new Uint8Array(currentMasterHeader.encryption.salt);
                const key = await Utils.deriveKeyFromPassword(password, salt);
                State.mut('currentEncryptionKey', key);
                
                // Test decryption on the first file to validate the key
                if (currentMasterHeader.files[0]) await Importer.extractFileBlob(currentMasterHeader.files[0]);
                
                State.mut('isContentUnlocked', true);
                UI.showToast('Password correct! Content unlocked.', 'success');
                Importer.refreshFileListView();
                elements.importPasswordPrompt.classList.add(CONFIG.CLASSES.hidden);
                elements.importPasswordInput.value = '';
                elements.pkgInfo.querySelector('[data-action="view-custom-data"]')?.classList.remove(CONFIG.CLASSES.hidden);

                const { pendingFileAction } = State.getState();
                if (pendingFileAction) {
                    App.handleFileAction(pendingFileAction.event, true);
                    State.mut('pendingFileAction', null);
                }
            } catch (e) {
                State.mut('currentEncryptionKey', null);
                State.mut('isContentUnlocked', false);
                UI.showToast(e.message || 'Incorrect password or corrupted file.', 'error');
                console.error(e);
            }
        },
        handleFileAction: async (event, force = false) => {
            const button = event.target.closest('button[data-action]');
            if (!button) return;

            const { action } = button.dataset;
            const { currentMasterHeader, isContentUnlocked } = State.getState();

            if (action === 'view-custom-data') {
                elements.customData.classList.toggle(CONFIG.CLASSES.hidden);
                return;
            }

            if (currentMasterHeader?.encryption && !isContentUnlocked && !force) {
                UI.showToast('Password needed to access file content.', 'warning');
                elements.importPasswordPrompt.classList.remove(CONFIG.CLASSES.hidden);
                State.mut('pendingFileAction', { event });
                return;
            }
            
            try {
                switch (action) {
                    case 'preview': {
                        const fileEntry = currentMasterHeader?.files[parseInt(button.dataset.index, 10)];
                        if (!fileEntry) return;
                        const fileItem = button.closest('.file-item');
                        const existingPreview = fileItem.nextElementSibling;
                        if (existingPreview?.classList.contains('inline-preview-container')) {
                            existingPreview.remove();
                        } else {
                            document.querySelector('.inline-preview-container')?.remove();
                            const blob = await Importer.extractFileBlob(fileEntry);
                            await Importer.displayPreview(blob, fileEntry.mime, fileItem);
                        }
                        break;
                    }
                    case 'save': {
                        const fileEntry = currentMasterHeader?.files[parseInt(button.dataset.index, 10)];
                        if (fileEntry) Utils.downloadBlob(await Importer.extractFileBlob(fileEntry), fileEntry.name.split('/').pop());
                        break;
                    }
                    case 'save-folder': {
                        const { folderName, filesJson } = button.dataset;
                        UI.showToast(`Creating zip for "${folderName}"...`, 'info');
                        const entries = JSON.parse(filesJson).map(name => currentMasterHeader.files.find(f => f.name === name)).filter(Boolean);
                        await App.createZipFromEntries(entries, `${folderName}.zip`);
                        break;
                    }
                    case 'save-all-zip': {
                        UI.showToast('Creating full package zip...', 'info');
                        await App.createZipFromEntries(currentMasterHeader.files, `package-all-files.zip`);
                        break;
                    }
                }
            } catch (e) { UI.showToast(`${action} failed: ${e.message}`, 'error'); console.error(e); }
        },
        handleConfigureMetadata: () => {
            if (State.getState().files.length === 0) {
                UI.showToast('Please add files before configuring metadata.', 'warning');
                return;
            }
            State.mut('isConfiguring', true);
            const tempHeader = State.getState().pendingMetadata || { created: Date.now(), version: 1 };
            
            Editor.displayMetadataForm(tempHeader);
            
            elements.editZone.parentElement.classList.add(CONFIG.CLASSES.hidden);
            elements.editKeyVerification.classList.add(CONFIG.CLASSES.hidden);
            elements.editDownload.classList.add(CONFIG.CLASSES.hidden);
            elements.editEncryptionSection.classList.add(CONFIG.CLASSES.hidden);
            elements.editForm.classList.remove(CONFIG.CLASSES.hidden);
            elements.editForm.dataset.locked = "false";
            elements.saveChanges.innerHTML = `<span aria-hidden="true">✅</span> Confirm Metadata`;
            
            App.switchToView('edit');
        },
        returnToCreateView: (switchView = true) => {
            State.mut('isConfiguring', false);
            elements.editZone.parentElement.classList.remove(CONFIG.CLASSES.hidden);
            elements.editDownload.classList.remove(CONFIG.CLASSES.hidden);
            elements.editForm.classList.add(CONFIG.CLASSES.hidden);
            elements.saveChanges.innerHTML = `<span aria-hidden="true">💾</span> Save Changes`;
            if (switchView) App.switchToView('create');
        },
        handleEditorLoad: async (packageFiles) => {
            if (!packageFiles || packageFiles.length === 0) return;
            Editor.clear();
            try {
                const loadedShards = await Promise.all([...packageFiles].map(Importer.readPackageHeader));
                const { masterHeader, sortedShards } = Importer.processHeaders(loadedShards);
                State.mut('shardsForEditing', sortedShards);
                State.mut('currentMasterHeader', masterHeader);
                elements.editForm.classList.remove(CONFIG.CLASSES.hidden);
                if (masterHeader.keyHash) {
                    elements.editKeyVerification.classList.remove(CONFIG.CLASSES.hidden);
                    elements.editForm.dataset.locked = "true";
                    State.mut('isEditorUnlocked', false);
                } else { Editor.unlockForm(masterHeader); }
                UI.showToast(`Loaded "${masterHeader.packageName || 'package'}" for editing.`, 'success');
            } catch (e) { UI.showToast(`Failed to load package: ${e.message}`, 'error'); console.error(e); Editor.clear(); }
        },
        handleVerifyEditorKey: async () => {
            const key = elements.masterKey.value;
            const { currentMasterHeader } = State.getState();
            if (!key || !currentMasterHeader?.keyHash) return;

            if (await Utils.computeStringSHA256(key) === currentMasterHeader.keyHash) {
                try {
                    await Utils.verifyHeaderSignature(currentMasterHeader, key);
                    UI.showToast('Key correct! Unlocking editor.', 'success');
                    Editor.unlockForm(currentMasterHeader);
                } catch (e) {
                    UI.showToast(`Error: ${e.message}`, 'error'); console.error(e);
                }
            } else { UI.showToast('Incorrect master key.', 'error'); }
        },
        handleSaveChanges: async () => {
            const { isConfiguring, isEditorUnlocked } = State.getState();
            if (isConfiguring) {
                try {
                    State.mut('pendingMetadata', Editor._getNewMetadataFromForm());
                    UI.showToast('Metadata configured successfully!', 'success');
                    App.returnToCreateView();
                } catch (e) { UI.showToast(e.message, 'error'); }
                return;
            }

            if (!isEditorUnlocked) return UI.showToast('Unlock the package with the master key first.', 'warning');
            const masterKey = elements.masterKey.value;
            if (!masterKey) return UI.showToast('Master key is required to sign and save changes.', 'warning');
            if (State.getState().isProcessing) return;

            State.setProcessing(true);
            UI.toggleProgress(true, 'Rebuilding package...');
            elements.editDownload.innerHTML = '';

            try {
                const newGlobalMetadata = Editor._getNewMetadataFromForm();
                const oldPassword = elements.editOldPassword.value;
                const newPassword = elements.editNewPassword.value;
                
                const editedShards = (oldPassword || newPassword)
                    ? await Editor._rebuildPackageWithEncryptionChanges(newGlobalMetadata, oldPassword, newPassword, masterKey)
                    : await Editor._updatePackageMetadataOnly(newGlobalMetadata, masterKey);

                UI.renderDownloadArea(editedShards, elements.editDownload);
                UI.showToast('Package saved successfully!', 'success');
            } catch (e) { UI.showToast(`Error saving package: ${e.message}`, 'error'); console.error(e); }
            finally { 
                State.setProcessing(false); 
                setTimeout(() => UI.toggleProgress(false), 1500);
            }
        },
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

        // --- Setup Methods ---
        setupEventListeners: () => {
            App._setupViewSwitching();
            App._setupCreateViewEvents();
            App._setupImportViewEvents();
            App._setupEditViewEvents();
            App._setupShareViewEvents();
            App._setupGlobalEvents();
        },
        _setupViewSwitching: () => {
            elements.switchToCreate.addEventListener('click', () => App.switchToView('create'));
            elements.switchToImport.addEventListener('click', () => App.switchToView('import'));
            elements.switchToEdit.addEventListener('click', () => App.switchToView('edit'));
            elements.switchToShare.addEventListener('click', () => App.switchToView('share'));
        },
        _setupCreateViewEvents: () => {
            elements.uploadZone.addEventListener('click', () => elements.fileInput.click());
            elements.fileInput.addEventListener('change', e => { State.addFiles([...e.target.files].map(f => ({ file: f, fullPath: f.name }))); e.target.value = ''; });
            elements.create.addEventListener('click', App.handleCreate);
            elements.clear.addEventListener('click', () => { if (State.getState().files.length > 0) { State.resetCreateView(); UI.showToast('All files cleared', 'success'); } });
            elements.copyKey.addEventListener('click', () => { navigator.clipboard.writeText(elements.masterKeyOutput.value); UI.showToast('Master key copied!', 'success'); });
            elements.splitSize.addEventListener('input', UI.updateCreateViewState);
            elements.configureMetadata.addEventListener('click', App.handleConfigureMetadata);
            elements.fileList.addEventListener('click', async (e) => {
                const button = e.target.closest('button[data-action]');
                if (!button) return;
                const { action, index } = button.dataset;
                if (action === 'remove') {
                    const { files } = State.getState();
                    const [removed] = files.splice(parseInt(index, 10), 1);
                    document.querySelector('.inline-preview-container')?.remove();
                    State.setFiles(files);
                    UI.showToast(`Removed "${removed.fullPath}"`, 'success');
                } else if (action === 'preview') {
                    const fileObject = State.getState().files[parseInt(index, 10)];
                    if (!fileObject) return;
                    const fileItem = button.closest('.file-item');
                    const existingPreview = fileItem.nextElementSibling;
                    if (existingPreview?.classList.contains('inline-preview-container')) {
                        existingPreview.remove();
                    } else {
                        document.querySelector('.inline-preview-container')?.remove();
                        await Importer.displayPreview(fileObject.file, fileObject.file.type, fileItem);
                    }
                }
            });
        },
        _setupImportViewEvents: () => {
            elements.importZone.addEventListener('click', () => elements.importInput.click());
            elements.importInput.addEventListener('change', e => { App.switchToView('import'); App.handleImport(e.target.files); e.target.value = ''; });
            elements.pkgInfo.addEventListener('click', App.handleFileAction);
            elements.unlockContent.addEventListener('click', App.handleUnlockContent);
        },
        _setupEditViewEvents: () => {
            elements.editZone.addEventListener('click', () => elements.editInput.click());
            elements.editInput.addEventListener('change', e => {
                const files = [...e.target.files]; e.target.value = '';
                if (files.length > 0) { App.switchToView('edit'); App.handleEditorLoad(files); }
            });
            elements.saveChanges.addEventListener('click', App.handleSaveChanges);
            elements.clearEdit.addEventListener('click', Editor.clear);
            elements.verifyKey.addEventListener('click', App.handleVerifyEditorKey);
        },
        _setupShareViewEvents: () => {
            elements.generateShareLink.addEventListener('click', App.handleGenerateShareLink);
            elements.copyShareLink.addEventListener('click', () => { navigator.clipboard.writeText(elements.shareLinkOutput.value); UI.showToast('Share link copied!', 'success'); });
        },
        _setupGlobalEvents: () => {
            const autoGrowTextareas = [elements.pkgDescription, elements.pkgCustomData, elements.shareUrls];
            autoGrowTextareas.forEach(textarea => {
                if (!textarea) return;
                const adjustHeight = () => { textarea.style.height = 'auto'; textarea.style.height = `${textarea.scrollHeight}px`; };
                textarea.addEventListener('input', adjustHeight);
                new ResizeObserver(adjustHeight).observe(textarea); // Handles initial render and other changes
            });
        },
        setupDragAndDrop: () => {
            const setupZone = (zone, onDrop) => {
                if (!zone) return;
                ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evName => zone.addEventListener(evName, e => { e.preventDefault(); e.stopPropagation(); }));
                ['dragenter', 'dragover'].forEach(evName => zone.addEventListener(evName, () => zone.classList.add(CONFIG.CLASSES.dragover)));
                ['dragleave', 'drop'].forEach(evName => zone.addEventListener(evName, () => zone.classList.remove(CONFIG.CLASSES.dragover)));
                zone.addEventListener('drop', onDrop);
            };

            setupZone(elements.uploadZone, async (e) => {
                if (State.getState().isProcessing) return;
                State.setProcessing(true);
                UI.showToast('Processing dropped items...', 'info');
                try {
                    const items = [...e.dataTransfer.items].map(item => item.webkitGetAsEntry());
                    const files = (await Promise.all(items.map(App.traverseFileTree))).flat();
                    State.addFiles(files);
                } catch (err) { UI.showToast('Could not process dropped items.', 'error'); console.error(err); }
                finally { State.setProcessing(false); }
            });
            setupZone(elements.importZone, (e) => { App.switchToView('import'); App.handleImport(e.dataTransfer.files); });
            setupZone(elements.editZone, (e) => { App.switchToView('edit'); App.handleEditorLoad(e.dataTransfer.files); });
        },
    };

    // --- GO ---
    App.init();
});