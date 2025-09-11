document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    //=================================================================================
    //  CONFIGURATION & CONSTANTS
    //=================================================================================
    const CONFIG = {
        CONSTANTS: {
            MAGIC: new TextEncoder().encode('NYXPKG1 '),    // 8-byte package identifier
            PACKAGE_FORMAT_VERSION: 5,                      // v5 introduced metadata protection via HMAC signature
            SHARE_KEY_MATERIAL: 'NYX-SHARE-OBFUSCATION-KEY-V1',
        },
        SELECTORS: {
            views: {
                createView: '#create-view', importView: '#import-view', editView: '#edit-view', shareView: '#share-view',
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

    //=================================================================================
    //  DOM ELEMENT CACHE & GLOBAL OBJECTS
    //=================================================================================
    const elements = Object.values(CONFIG.SELECTORS).reduce((acc, group) => {
        for (const [key, selector] of Object.entries(group)) {
            acc[key] = document.querySelector(selector);
        }
        return acc;
    }, {});
    
    // Make key objects globally available within the scope of all scripts
    window.CONFIG = CONFIG;
    window.elements = elements;


    //=================================================================================
    //  STATE MANAGEMENT
    //=================================================================================
    const State = (() => {
        const _state = {
            files: [],                  // Files staged for package creation
            isProcessing: false,        // Global flag for long-running tasks
            currentImportedShards: [],  // Shard data for the imported package
            currentMasterHeader: null,  // Assembled header from imported shards
            activePreviewUrl: null,     // Object URL for the current preview to allow revocation
            shardsForEditing: [],       // Shard data for the package being edited
            isEditorUnlocked: false,    // Flag indicating if the editor form is unlocked
            currentEncryptionKey: null, // CryptoKey object for decryption
            pendingFileAction: null,    // Caches a file action (e.g., download) while waiting for password
            isContentUnlocked: false,   // Flag indicating if encrypted content is accessible
            pendingMetadata: null,      // Caches metadata from the configuration step
            isConfiguring: false,       // Flag for when the editor is used for pre-creation metadata config
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
    window.State = State;


    //=================================================================================
    //  UTILITY MODULE
    //=================================================================================
    const Utils = {
        // Converts bytes to a human-readable string (KB, MB, GB)
        humanSize: bytes => {
            if (bytes === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${units[i]}`;
        },

        // Escapes HTML special characters in a string
        escapeHtml: text => String(text ?? '').replace(/[&<>"']/g, match => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[match])),

        /** Triggers a browser download for a given Blob. */
        downloadBlob: (blob, filename) => {
            const url = URL.createObjectURL(blob);
            const a = Object.assign(document.createElement('a'), { href: url, download: filename, style: "display: none;" });
            document.body.appendChild(a).click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 60000);
        },

        // Converts a BigInt to an 8-byte big-endian Uint8Array
        bigIntTo8Bytes: n => {
            const buf = new ArrayBuffer(8);
            new DataView(buf).setBigUint64(0, BigInt(n), false);
            return new Uint8Array(buf);
        },

        // Reads an 8-byte big-endian Uint8Array into a BigInt
        readBigInt8Bytes: bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, false),

        // Computes the SHA-256 hash of a string
        computeStringSHA256: async str => {
            const buf = new TextEncoder().encode(str);
            const hashBuf = await crypto.subtle.digest('SHA-256', buf);
            return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
        },

        // Generates a cryptographically random string for the master key
        generateMasterKey: (length = 42) => {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            const randomValues = new Uint32Array(length);
            crypto.getRandomValues(randomValues);
            return Array.from(randomValues, val => chars[val % chars.length]).join('');
        },

        // Formats a Date object into a local ISO-like string for datetime-local input
        dateToLocalISO: date => {
            const tzoffset = date.getTimezoneOffset() * 60000;
            return new Date(date.getTime() - tzoffset).toISOString().slice(0, 16);
        },

        // Obfuscates a filename for display when content is locked
        censorFilename: path => path.split('/').map(part => {
            const lastDot = part.lastIndexOf('.');
            if (lastDot <= 0) return '*'.repeat(part.length);
            const name = part.substring(0, lastDot);
            const ext = part.substring(lastDot);
            return '*'.repeat(name.length) + ext;
        }).join('/'),

        // Derives an AES-GCM CryptoKey from a password and salt using PBKDF2
        deriveKeyFromPassword: async (password, salt) => {
            const enc = new TextEncoder().encode(password);
            const keyMaterial = await crypto.subtle.importKey('raw', enc, { name: 'PBKDF2' }, false, ['deriveKey']);
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
            );
        },

        // Encrypts a Blob using AES-GCM
        encryptBlob: async (blob, key) => {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const data = await blob.arrayBuffer();
            const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
            return { encryptedBlob: new Blob([encryptedData]), iv: Array.from(iv) };
        },

        // Decrypts a Blob using AES-GCM
        decryptBlob: async (encryptedBlob, key, iv) => {
            const data = await encryptedBlob.arrayBuffer();
            const ivBytes = new Uint8Array(iv);
            const decryptedData = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, data);
            return new Blob([decryptedData]);
        },

        // Derives an HMAC key from the master key string
        getHmacKey: async (masterKey) => {
            const keyData = new TextEncoder().encode(masterKey);
            return crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
        },

        // Generates an HMAC signature for a package header object
        generateHeaderSignature: async (headerObject, masterKey) => {
            const key = await Utils.getHmacKey(masterKey);
            const { headerSignature, ...signableHeader } = headerObject;
            const canonicalString = JSON.stringify(Object.keys(signableHeader).sort().reduce((obj, key) => {
                obj[key] = signableHeader[key]; return obj;
            }, {}));
            const signatureBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(canonicalString));
            return Array.from(new Uint8Array(signatureBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        },

        // Verifies the HMAC signature of a package header
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
    window.Utils = Utils;


    //=================================================================================
    //  UI MODULE (SHARED FUNCTIONS)
    //=================================================================================
    const UI = {
        // Displays a toast notification
        showToast: (message, type = 'info', duration = 4000) => {
            if (!elements.toast) return;
            const toast = Object.assign(document.createElement('div'), { className: `toast ${type}`, textContent: message, role: 'status' });
            elements.toast.appendChild(toast);
            if (duration > 0) setTimeout(() => toast.remove(), duration);
            return toast;
        },

        // Updates the progress bar
        updateProgress: (percent, text) => {
            const clampedPercent = Math.max(0, Math.min(100, percent));
            elements.progressFill.style.width = `${clampedPercent}%`;
            elements.progressFill.setAttribute('aria-valuenow', String(clampedPercent));
            if (text) elements.progressText.textContent = text;
        },

        // Shows or hides the progress bar
        toggleProgress: (show, text = 'Preparing...') => {
            elements.progress.classList.toggle(CONFIG.CLASSES.hidden, !show);
            if (show) UI.updateProgress(0, text);
        },

        // Returns an appropriate emoji icon for a given MIME type
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
        
        // Renders download links for generated package files
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
                const button = Object.assign(document.createElement('button'), { 
                    className: 'btn btn-primary', 
                    innerHTML: `💾 Download All as .zip` 
                });
                button.onclick = async () => {
                    if (State.getState().isProcessing) return;
                    State.setProcessing(true);
                    const toast = UI.showToast('Zipping files...', 'info', 0);
                    try {
                        const zip = new JSZip();
                        files.forEach(f => zip.file(f.filename, f.blob));
                        const zipBlob = await zip.generateAsync({ type: "blob" });
                        Utils.downloadBlob(zipBlob, `package-shards.zip`);
                        UI.showToast('ZIP archive created!', 'success');
                    } catch (e) { 
                        UI.showToast(`Failed to create zip: ${e.message}`, 'error'); 
                        console.error(e); 
                    } finally { 
                        State.setProcessing(false); 
                        toast.remove();
                    }
                };
                targetElement.prepend(button);
            }
        },
    };
    window.UI = UI;


    //=================================================================================
    //  PACKER MODULE
    //=================================================================================
    const Packer = {
        // Assembles a single .nyx package Blob from a header and payload
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

        // Determines whether to build a single or split package
        buildFromPayloads: async (baseHeader, finalPayloads, splitSizeBytes, masterKey = null) => {
            const totalPayloadSize = finalPayloads.reduce((sum, blob) => sum + blob.size, 0);
            if (splitSizeBytes > 0 && totalPayloadSize > splitSizeBytes) {
                return Packer.buildSplitPackage(baseHeader, finalPayloads, splitSizeBytes, masterKey);
            }
            return Packer.buildSinglePackage(baseHeader, finalPayloads, masterKey);
        },

        // Builds a single, non-split .nyx package
        buildSinglePackage: async (baseHeader, payloads, masterKey = null) => {
            UI.updateProgress(90, 'Building package header...');
            let offset = 0;
            const finalEntriesWithOffset = baseHeader.files.map(e => ({ ...e, offset: (offset += e.length) - e.length }));
            const headerObj = { ...baseHeader, files: finalEntriesWithOffset, totalSize: offset };
            const builtPackage = await Packer.buildBlob(headerObj, payloads, 'package', masterKey);
            UI.updateProgress(100, 'Finalizing...');
            return [builtPackage];
        },

        // Builds a multi-file, split (sharded) .nyx package
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

        // Main package creation orchestrator
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
    window.Packer = Packer;

    //=================================================================================
    //  IMPORTER MODULE (CORE LOGIC)
    //=================================================================================
    const Importer = {
        // Reads and parses the header of a .nyx package file
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

        // Processes multiple shard headers to assemble a single master header
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

        // Extracts the raw (potentially encrypted) Blob for a file from its shards
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

        // Extracts and decrypts (if necessary) the Blob for a file
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
    };
    window.Importer = Importer;


    //=================================================================================
    //  APP CONTROLLER & EVENT HANDLER
    //=================================================================================
    const App = {
        // Initializes the application
        init() {
            console.log("Nyx Packer App Initializing...");
            App.setupEventListeners();
            App.setupDragAndDrop();
            App.loadShardsFromUrl();
            UI.updateCreateViewState();
            UI.showToast('Application ready!', 'success');
        },

        // Checks for and loads package shards from URL parameters
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
            const importToast = UI.showToast(`Starting import of ${shardUrls.length} shard(s)...`, 'info', 0);

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

        // Switches the currently visible view
        switchToView: (viewName) => {
            console.info(`Switching to view: ${viewName}`);
            const { isConfiguring } = State.getState();
            const currentView = document.querySelector(`.${CONFIG.CLASSES.activeView}`);
            if (currentView?.id === 'edit-view' && isConfiguring && viewName !== 'edit') {
                 App.returnToCreateView(false); // Don't switch view again
            }

            Object.values(CONFIG.SELECTORS.views).forEach(selector => document.querySelector(selector)?.classList.remove(CONFIG.CLASSES.activeView));
            const viewKey = `${viewName}View`;
            elements[viewKey]?.classList.add(CONFIG.CLASSES.activeView);
            
            document.querySelectorAll('.switcher-btn').forEach(btn => {
                const isActive = btn.id === `switchTo${viewName.charAt(0).toUpperCase() + viewName.slice(1)}`;
                btn.classList.toggle(CONFIG.CLASSES.activeBtn, isActive);
                btn.setAttribute('aria-pressed', String(isActive));
            });
        },

        // Recursively traverses a dropped file system entry (file or directory)
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

        // Creates and downloads a ZIP archive from a list of file entries
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

        // Attaches all necessary event listeners
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
        
        _setupGlobalEvents: () => {
            const autoGrowTextareas = [elements.pkgDescription, elements.pkgCustomData, elements.shareUrls];
            autoGrowTextareas.forEach(textarea => {
                if (!textarea) return;
                const adjustHeight = () => { textarea.style.height = 'auto'; textarea.style.height = `${textarea.scrollHeight}px`; };
                textarea.addEventListener('input', adjustHeight);
                new ResizeObserver(adjustHeight).observe(textarea);
            });
        },

        // Sets up drag and drop functionality for all relevant zones
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
    window.App = App;

    // INITIALIZE THE APP
    App.init();
});