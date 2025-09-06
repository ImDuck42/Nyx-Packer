document.addEventListener('DOMContentLoaded', () => {

    // --- Configuration and Constants ---
    const CONFIG = {
        MAGIC: new TextEncoder().encode('NYXPKG1 '), // 8-byte package identifier
        CURRENT_VERSION: 4, // Version 4 introduced content encryption
        SELECTORS: {
            views: { 
                createView: '#create-view', 
                importView: '#import-view', 
                editView: '#edit-view' 
            },
            buttons: {
                switchToCreate: '#switchToCreate', switchToImport: '#switchToImport', switchToEdit: '#switchToEdit',
                create: '#createBtn', clear: '#clearBtn', copyKey: '#copyKeyBtn', clearPreview: '#clearPreviewBtn',
                verifyKey: '#verifyKeyBtn', saveChanges: '#saveChangesBtn', clearEdit: '#clearEditBtn',
                unlockContent: '#unlockContentBtn', configureMetadata: '#configureMetadataBtn',
            },
            inputs: {
                fileInput: '#fileInput', importInput: '#importInput', editInput: '#editInput', splitSize: '#splitSize',
                masterKey: '#masterKeyInput', encryptionPassword: '#encryptionPassword',
                importPasswordInput: '#importPasswordInput', editOldPassword: '#editOldPassword', editNewPassword: '#editNewPassword',
            },
            zones: { 
                uploadZone: '#uploadZone', importZone: '#importZone', editZone: '#editZone' 
            },
            displays: {
                fileList: '#fileList', shardInfo: '#shardInfo', totalSizeInfo: '#totalSizeInfo',
                progress: '#createProgress', progressFill: '#progressFill', progressText: '#progressText',
                masterKeyArea: '#masterKeyArea', masterKeyOutput: '#masterKeyOutput', pkgInfo: '#pkgInfo',
                previewHeader: '#previewHeader', previewContent: '#previewContent', importPasswordPrompt: '#importPasswordPrompt',
                editEncryptionStatus: '#editEncryptionStatus', customDataContent: '#customDataContent',
            },
            containers: {
                download: '#downloadArea', editDownload: '#editDownloadArea',
                editForm: '#editFormContainer', editKeyVerification: '#editKeyVerification', toast: '#toastContainer',
                editEncryptionSection: '#editEncryptionSection', editOldPasswordGroup: '#editOldPasswordGroup',
                customData: '#customDataContainer',
            },
            forms: {
                metadata: '#metadataForm', pkgName: '#pkgName', pkgAuthor: '#pkgAuthor', pkgDescription: '#pkgDescription',
                pkgSource: '#pkgSource', pkgTags: '#pkgTags', pkgVersion: '#pkgVersion', pkgCreated: '#pkgCreated', pkgCustomData: '#pkgCustomData',
            },
            templates: { fileItem: '#file-item-template' },
        },
        CLASSES: { hidden: 'hidden', dragover: 'dragover', activeView: 'active-view', activeBtn: 'active' },
        SUPPORTED_PREVIEW_TYPES: {
            image: ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'],
            video: ['video/mp4', 'video/webm', 'video/ogg'],
            audio: ['audio/mp3', 'audio/wav', 'audio/ogg', 'audio/m4a'],
            text: ['text/plain', 'text/html', 'text/css', 'text/javascript', 'application/json'],
            archive: ['application/zip', 'application/x-zip-compressed'],
        }
    };

    // --- Global Application State ---
    const state = {
        files: [], isProcessing: false, currentImportedShards: [], currentMasterHeader: null,
        activePreviewUrl: null, shardsForEditing: [], isEditorUnlocked: false,
        currentEncryptionKey: null, pendingFileAction: null, isContentUnlocked: false,
        pendingMetadata: null, isConfiguring: false,
    };

    // --- DOM Element Cache ---
    const elements = Object.values(CONFIG.SELECTORS).reduce((acc, group) => {
        Object.entries(group).forEach(([key, selector]) => { acc[key] = document.querySelector(selector); });
        return acc;
    }, {});

    // --- Utility Module ---
    const Utils = {
        /** Converts bytes to a human-readable string. @param {number} bytes - The number of bytes. @returns {string} */
        humanSize: bytes => {
            if (bytes === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${units[i]}`;
        },
        /** Escapes HTML special characters in a string. @param {string} text - The string to escape. @returns {string} */
        escapeHtml: text => {
            const str = String(text ?? '');
            return str.replace(/[&<>"']/g, match => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[match]));
        },
        /** Triggers a browser download for a Blob. @param {Blob} blob - The blob to download. @param {string} filename - The desired filename. */
        downloadBlob: (blob, filename) => {
            const url = URL.createObjectURL(blob);
            const a = Object.assign(document.createElement('a'), { href: url, download: filename });
            document.body.appendChild(a).click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 60000);
        },
        /** Converts a BigInt to an 8-byte Uint8Array (Big Endian). @param {bigint} n - The BigInt to convert. @returns {Uint8Array} */
        bigIntTo8Bytes: n => {
            const buf = new ArrayBuffer(8);
            new DataView(buf).setBigUint64(0, BigInt(n), false);
            return new Uint8Array(buf);
        },
        /** Reads an 8-byte Uint8Array into a BigInt (Big Endian). @param {Uint8Array} bytes - The bytes to read. @returns {bigint} */
        readBigInt8Bytes: bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, false),
        /** Computes the SHA-256 hash of a string. @param {string} str - The input string. @returns {Promise<string>} The hex-encoded hash. */
        computeStringSHA256: async str => {
            const buf = new TextEncoder().encode(str);
            const hashBuf = await crypto.subtle.digest('SHA-256', buf);
            return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
        },
        /** Generates a random alphanumeric master key. @param {number} length - The desired key length. @returns {string} */
        generateMasterKey: (length = 42) => {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            const randomValues = new Uint32Array(length);
            crypto.getRandomValues(randomValues);
            return Array.from(randomValues, val => chars[val % chars.length]).join('');
        },
        /** Formats a Date object into a string for datetime-local input. @param {Date} date - The date to format. @returns {string} */
        dateToLocalISO: date => {
            const tzoffset = date.getTimezoneOffset() * 60000;
            return new Date(date.getTime() - tzoffset).toISOString().slice(0, 16);
        },
        /** Censors a filename for display when locked. @param {string} path - The file path. @returns {string} */
        censorFilename: path => {
            return path.split('/').map(part => {
                const lastDot = part.lastIndexOf('.');
                if (lastDot <= 0) return '*'.repeat(part.length);
                const name = part.substring(0, lastDot);
                const ext = part.substring(lastDot);
                return '*'.repeat(name.length) + ext;
            }).join('/');
        },
        /** Derives a CryptoKey from a password and salt using PBKDF2. @param {string} password - The user's password. @param {Uint8Array} salt - The salt. @returns {Promise<CryptoKey>} */
        deriveKeyFromPassword: async (password, salt) => {
            const enc = new TextEncoder().encode(password);
            const keyMaterial = await crypto.subtle.importKey('raw', enc, { name: 'PBKDF2' }, false, ['deriveKey']);
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
            );
        },
        /** Encrypts a Blob using AES-GCM. @param {Blob} blob - The blob to encrypt. @param {CryptoKey} key - The encryption key. @returns {Promise<{encryptedBlob: Blob, iv: number[]}>} */
        encryptBlob: async (blob, key) => {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const data = await blob.arrayBuffer();
            const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
            return { encryptedBlob: new Blob([encryptedData]), iv: Array.from(iv) };
        },
        /** Decrypts a Blob using AES-GCM. @param {Blob} encryptedBlob - The blob to decrypt. @param {CryptoKey} key - The decryption key. @param {number[]} iv - The initialization vector. @returns {Promise<Blob>} */
        decryptBlob: async (encryptedBlob, key, iv) => {
            const data = await encryptedBlob.arrayBuffer();
            const ivBytes = new Uint8Array(iv);
            const decryptedData = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, data);
            return new Blob([decryptedData]);
        },
    };

    // --- UI Module (Handles all DOM manipulations) ---
    const UI = {
        /** Shows a toast notification. @param {string} message - The message to display. @param {'info'|'success'|'error'|'warning'} type - The toast type. @param {number} duration - Duration in ms. */
        showToast: (message, type = 'info', duration = 4000) => {
            if (!elements.toast) return;
            const toast = Object.assign(document.createElement('div'), { className: `toast ${type}`, textContent: message, role: 'status', 'aria-live': 'polite' });
            elements.toast.appendChild(toast);
            setTimeout(() => toast.remove(), duration);
        },
        /** Updates the progress bar. @param {number} percent - The percentage (0-100). @param {string} [text] - Optional text to display. */
        updateProgress: (percent, text) => {
            const clampedPercent = Math.max(0, Math.min(100, percent));
            elements.progressFill.style.width = `${clampedPercent}%`;
            elements.progressFill.setAttribute('aria-valuenow', String(clampedPercent));
            if (text) elements.progressText.textContent = text;
        },
        /** Toggles the visibility of the progress bar. @param {boolean} show - Whether to show the progress bar. @param {string} [text='Preparing...'] - Initial text. */
        toggleProgress: (show, text = 'Preparing...') => {
            elements.progress.classList.toggle(CONFIG.CLASSES.hidden, !show);
            if (show) UI.updateProgress(0, text);
        },
        /** Gets an appropriate emoji icon for a MIME type. @param {string} mimeType - The file's MIME type. @returns {string} The icon. */
        getFileIcon: mimeType => {
            if (!mimeType) return '📄';
            if (state.currentMasterHeader?.encryption && !state.isContentUnlocked) return '🔒';
            if (mimeType.startsWith('image/')) return '🖼️';
            if (mimeType.startsWith('video/')) return '🎬';
            if (mimeType.startsWith('audio/')) return '🎵';
            if (mimeType.startsWith('text/')) return '📝';
            if (mimeType.includes('pdf')) return '📕';
            if (CONFIG.SUPPORTED_PREVIEW_TYPES.archive.includes(mimeType)) return '📦';
            return '📄';
        },
        /** Renders the list of files in the Create view. */
        renderFileList: () => {
            elements.fileList.innerHTML = '';
            const fragment = document.createDocumentFragment();
            state.files.forEach((fileObject, index) => {
                const itemTemplate = elements.fileItem.content.cloneNode(true);
                const item = itemTemplate.querySelector('.file-item');
                item.querySelector('.file-icon').textContent = UI.getFileIcon(fileObject.file.type);
                Object.assign(item.querySelector('.file-name'), { textContent: fileObject.fullPath, title: fileObject.fullPath });
                item.querySelector('.file-size').textContent = Utils.humanSize(fileObject.file.size);
                item.querySelector('[data-action="remove"]').dataset.index = String(index);
                fragment.appendChild(itemTemplate);
            });
            elements.fileList.appendChild(fragment);
        },
        /** Updates the state of UI elements in the Create view based on the current app state. */
        updateCreateViewState: () => {
            UI.renderFileList();
            const hasFiles = state.files.length > 0;
            elements.create.disabled = !hasFiles || state.isProcessing;
            elements.configureMetadata.disabled = !hasFiles || state.isProcessing;
            const totalSize = state.files.reduce((sum, f) => sum + f.file.size, 0);
            elements.totalSizeInfo.textContent = totalSize > 0 ? `Total: ${Utils.humanSize(totalSize)}` : '';
            const splitSizeMB = parseFloat(elements.splitSize.value);
            if (!totalSize || isNaN(splitSizeMB) || splitSizeMB <= 0) {
                elements.shardInfo.textContent = ''; return;
            }
            const splitSizeBytes = splitSizeMB * 1024 * 1024;
            elements.shardInfo.textContent = totalSize > splitSizeBytes ? `(≈ ${Math.ceil(totalSize / splitSizeBytes)} shards)` : '';
        },
        /** Renders download links for generated files. @param {{blob: Blob, filename: string}[]} files - An array of file objects. @param {HTMLElement} targetElement - The container to render into. */
        renderDownloadArea: (files, targetElement) => {
            targetElement.innerHTML = '';
            if (files.length === 0) return;

            const allContainer = document.createElement('div');
            const linksContainer = Object.assign(document.createElement('div'), { className: 'download-links-container' });

            files.forEach(file => {
                const url = URL.createObjectURL(file.blob);
                const link = Object.assign(document.createElement('a'), { href: url, download: file.filename, className: 'download-link' });
                link.innerHTML = `<strong>${Utils.escapeHtml(file.filename)}</strong> <small>(${Utils.humanSize(file.blob.size)})</small>`;
                linksContainer.appendChild(link);
                setTimeout(() => URL.revokeObjectURL(url), 300000); // Clean up URLs after 5 minutes
            });

            if (files.length > 1) {
                const button = Object.assign(document.createElement('button'), { className: 'btn btn-primary', innerHTML: `💾 Download All as .zip` });
                button.onclick = async () => {
                    if (state.isProcessing) return;
                    state.isProcessing = true;
                    UI.showToast('Zipping files...', 'info');
                    try {
                        const zip = new JSZip();
                        files.forEach(f => zip.file(f.filename, f.blob));
                        const zipBlob = await zip.generateAsync({ type: "blob" });
                        Utils.downloadBlob(zipBlob, `package-shards.zip`);
                        UI.showToast('ZIP archive created!', 'success');
                    } catch (e) { UI.showToast(`Failed to create zip: ${e.message}`, 'error'); console.error(e); }
                    finally { state.isProcessing = false; }
                };
                allContainer.appendChild(button);
            }
            targetElement.appendChild(allContainer);
            targetElement.appendChild(linksContainer);
        }
    };

    // --- Packer Module (File Creation Logic) ---
    const Packer = {
        /** Assembles a .nyx package Blob from a header and payload. @param {object} headerObj - The JSON header. @param {Blob[]} payloadBlobs - Array of file blobs. @param {string} baseName - Base name for the file. @returns {Promise<{blob: Blob, filename: string}>} */
        buildBlob: async (headerObj, payloadBlobs, baseName) => {
            const headerBytes = new TextEncoder().encode(JSON.stringify(headerObj));
            const headerLenBuf = Utils.bigIntTo8Bytes(headerBytes.length);
            const blob = new Blob([CONFIG.MAGIC, headerLenBuf, headerBytes, ...payloadBlobs], { type: 'application/octet-stream' });
            const filename = `${baseName}-${new Date().toISOString().replace(/[:.]/g, '-')}.nyx`;
            return { blob, filename };
        },
        /** Creates file entry objects for the package header from the current state. @returns {object[]} */
        createFileEntries: () => state.files.map(({ file, fullPath }) => ({ name: fullPath, mime: file.type || 'application/octet-stream', length: file.size, lastModified: file.lastModified ?? Date.now() })),
        /** Builds a single or multi-part (sharded) package based on size. @param {object} baseHeader - The base header object. @param {Blob[]} finalPayloads - Array of file content blobs. @param {number} splitSizeBytes - The max size of a shard in bytes, or 0 for no split. @param {HTMLElement} progressElement - The progress container element. @param {HTMLElement} downloadElement - The download container element. */
        buildFromPayloads: async (baseHeader, finalPayloads, splitSizeBytes, progressElement, downloadElement) => {
            const totalPayloadSize = finalPayloads.reduce((sum, blob) => sum + blob.size, 0);
            if (splitSizeBytes > 0 && totalPayloadSize > splitSizeBytes) {
                await Packer.buildSplitPackage(baseHeader, finalPayloads, splitSizeBytes, progressElement, downloadElement);
            } else {
                await Packer.buildSinglePackage(baseHeader, finalPayloads, progressElement, downloadElement);
            }
        },
        /** Builds a single, non-sharded package. (Called by buildFromPayloads) */
        buildSinglePackage: async (baseHeader, payloads, progressElement, downloadElement) => {
            UI.updateProgress(90, 'Building package header...');
            let offset = 0;
            const finalEntriesWithOffset = baseHeader.files.map(e => ({ ...e, offset: (offset += e.length) - e.length }));
            const headerObj = { ...baseHeader, files: finalEntriesWithOffset, totalSize: offset };
            const builtPackage = await Packer.buildBlob(headerObj, payloads, 'package');
            UI.updateProgress(100, 'Finalizing...');
            UI.renderDownloadArea([builtPackage], downloadElement);
        },
        /** Builds a sharded package. (Called by buildFromPayloads) */
        buildSplitPackage: async (baseHeader, payloads, splitSizeBytes, progressElement, downloadElement) => {
            const shardData = [];
            const packageId = `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
            let shardNum = 1;
            let currentShard = { payload: [], entries: [], size: 0 };
            const totalPayloadSize = payloads.reduce((sum, p) => sum + p.size, 0);
            const totalShardsEstimate = Math.max(1, Math.ceil(totalPayloadSize / splitSizeBytes));

            const finalizeCurrentShard = async () => {
                if (currentShard.payload.length === 0) return;
                const headerObj = { ...baseHeader, files: currentShard.entries, totalSize: currentShard.size, splitInfo: { id: packageId, shard: shardNum, total: totalShardsEstimate } };
                shardData.push(await Packer.buildBlob(headerObj, currentShard.payload, `package-shard${shardNum}`));
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
            UI.renderDownloadArea(shardData, downloadElement);
            UI.showToast(`Package successfully split into ${shardNum - 1} shards.`, 'success');
        },
        /** Main handler for the 'Create Package' button click. */
        handleCreate: async () => {
            if (state.files.length === 0) return UI.showToast('Please add at least one file', 'warning');
            if (state.isProcessing) return;

            state.isProcessing = true;
            UI.updateCreateViewState();
            elements.download.innerHTML = '';
            elements.masterKeyArea.classList.add(CONFIG.CLASSES.hidden);
            UI.toggleProgress(true, 'Preparing package...');

            try {
                const masterKey = Utils.generateMasterKey();
                const keyHash = await Utils.computeStringSHA256(masterKey);
                const entries = Packer.createFileEntries();
                
                const metadata = state.pendingMetadata || {};
                const baseHeader = { 
                    ...metadata,
                    version: CONFIG.CURRENT_VERSION, 
                    created: metadata.created || Date.now(), 
                    keyHash, 
                    files: entries 
                };

                const splitSizeMB = parseFloat(elements.splitSize.value);
                const splitSizeBytes = !isNaN(splitSizeMB) && splitSizeMB > 0 ? splitSizeMB * 1024 * 1024 : 0;
                
                const finalPayloads = [];
                const password = elements.encryptionPassword.value;
                
                if (password) {
                    UI.updateProgress(10, "Deriving encryption key...");
                    const salt = crypto.getRandomValues(new Uint8Array(16));
                    const encryptionKey = await Utils.deriveKeyFromPassword(password, salt);
                    baseHeader.encryption = { salt: Array.from(salt) };

                    for (let i = 0; i < state.files.length; i++) {
                        UI.updateProgress(10 + (i / state.files.length * 70), `Encrypting ${state.files[i].fullPath}...`);
                        const { encryptedBlob, iv } = await Utils.encryptBlob(state.files[i].file, encryptionKey);
                        finalPayloads.push(encryptedBlob);
                        baseHeader.files[i].iv = iv;
                        baseHeader.files[i].length = encryptedBlob.size;
                    }
                } else {
                    finalPayloads.push(...state.files.map(f => f.file));
                }
                
                await Packer.buildFromPayloads(baseHeader, finalPayloads, splitSizeBytes, elements.progress, elements.download);

                elements.masterKeyOutput.value = masterKey;
                elements.masterKeyArea.classList.remove(CONFIG.CLASSES.hidden);
                UI.showToast('Package created successfully!', 'success');

            } catch (e) { UI.showToast(`Package creation failed: ${e.message}`, 'error'); console.error(e); }
            finally {
                state.isProcessing = false;
                state.pendingMetadata = null;
                UI.updateCreateViewState();
                elements.encryptionPassword.value = '';
                setTimeout(() => UI.toggleProgress(false), 1000);
            }
        },
    };

    // --- Importer Module (File Extraction Logic) ---
    const Importer = {
        /** Reads and parses the header from a .nyx package file. @param {File} packageFile - The .nyx file. @returns {Promise<{header: object, payloadStart: number, packageFile: File}>} */
        readPackageHeader: async (packageFile) => {
            if (!packageFile.name.toLowerCase().endsWith('.nyx')) throw new Error(`Invalid file type: ${packageFile.name}`);
            const headerBuffer = await packageFile.slice(0, 16).arrayBuffer();
            const headerBytes = new Uint8Array(headerBuffer);
            if (new TextDecoder().decode(headerBytes.slice(0, 8)) !== new TextDecoder().decode(CONFIG.MAGIC)) throw new Error('Invalid package file (bad magic header)');
            const headerLength = Number(Utils.readBigInt8Bytes(headerBytes.slice(8, 16)));
            const headerEnd = 16 + headerLength;
            const headerJsonBuffer = await packageFile.slice(16, headerEnd).arrayBuffer();
            try {
                const header = JSON.parse(new TextDecoder().decode(headerJsonBuffer));
                return { header, payloadStart: headerEnd, packageFile };
            } catch (e) { throw new Error('Invalid package file (corrupted header)'); }
        },
        /** Processes multiple shard headers to reconstruct a single master header. @param {{header: object}[]} headers - An array of parsed header objects. @returns {{masterHeader: object, sortedShards: object[]}} */
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
        /** Extracts the raw (potentially encrypted) blob for a file entry from its shards. @param {object} fileEntry - The file's master header entry. @param {object[]} sourceShards - The sorted shard objects. @returns {Promise<Blob>} */
        _extractRawFileBlob: async (fileEntry, sourceShards) => {
             if (!fileEntry.chunks || fileEntry.chunks.length === 0) {
                const shard = sourceShards[0];
                return shard.packageFile.slice(shard.payloadStart + fileEntry.offset, shard.payloadStart + fileEntry.offset + fileEntry.length);
            }
            const chunkBlobs = await Promise.all(fileEntry.chunks.map(chunk => {
                const shard = sourceShards.find(s => s.header.splitInfo.shard === chunk.shard);
                if (!shard) throw new Error(`Could not find shard #${chunk.shard} for file "${fileEntry.name}"`);
                return shard.packageFile.slice(shard.payloadStart + chunk.offset, shard.payloadStart + chunk.offset + chunk.length).arrayBuffer();
            }));
            return new Blob(chunkBlobs);
        },
        /** Extracts and decrypts (if necessary) the blob for a file entry. @param {object} fileEntry - The file's master header entry. @returns {Promise<Blob>} The final file blob. */
        extractFileBlob: async (fileEntry) => {
            const rawBlob = await Importer._extractRawFileBlob(fileEntry, state.currentImportedShards);
            if (state.currentMasterHeader.encryption) {
                if (!state.currentEncryptionKey) throw new Error("Encryption key not available.");
                try {
                    UI.showToast(`Decrypting ${Utils.censorFilename(fileEntry.name)}...`, 'info', 1500);
                    const decryptedBlob = await Utils.decryptBlob(rawBlob, state.currentEncryptionKey, fileEntry.iv);
                    return new Blob([await decryptedBlob.arrayBuffer()], { type: fileEntry.mime });
                } catch (e) {
                    console.error("Decryption failed:", e);
                    throw new Error("Decryption failed. The password may be incorrect.");
                }
            }
            return new Blob([await rawBlob.arrayBuffer()], { type: fileEntry.mime });
        },
        /** Displays the main package information in the UI. @param {object} header - The master header. @param {number} totalSize - Total size of all shard files. */
        displayPackageInfo: (header, totalSize) => {
            const details = {
                'Author': header.author, 'Source': header.source, 'Files': header.files.length, 'Total Size': Utils.humanSize(totalSize),
                'Created': new Date(header.created || 0).toLocaleString(), 'Package Version': header.version ?? 1,
                'Encryption': header.encryption ? 'AES-GCM' : 'None',
            };
            const detailsHtml = Object.entries(details).filter(([, v]) => v).map(([k, v]) => `<div><strong>${k}:</strong> ${Utils.escapeHtml(v)}</div>`).join('');
            const descriptionHtml = header.description ? `<p class="package-description">${Utils.escapeHtml(header.description)}</p>` : '';
            const tagsHtml = header.tags?.length ? `<div class="package-tags">${header.tags.map(tag => `<span class="tag">${Utils.escapeHtml(tag)}</span>`).join('')}</div>` : '';
            const shardInfo = state.currentImportedShards.length > 1 ? `<div><strong>Shards:</strong> ${state.currentImportedShards.length}</div>` : '';
            const customDataButton = header.customData ? `<button class="btn btn-secondary btn-small ${header.encryption ? 'hidden' : ''}" data-action="view-custom-data">View Custom Data</button>` : '';

            elements.pkgInfo.innerHTML = `
                <div class="package-summary">
                    <h3>📦 Package: <span class="pkg-name">${Utils.escapeHtml(header.packageName) || 'Untitled'}</span></h3>
                    ${descriptionHtml}${tagsHtml}
                    <div class="package-details-grid">${detailsHtml}${shardInfo}</div>
                    <div class="view-actions">
                        <button class="btn btn-primary" data-action="save-all-zip">💾 Download All as .zip</button>
                        ${customDataButton}
                    </div>
                </div>`;
            
            if(header.customData) {
                elements.customDataContent.textContent = JSON.stringify(header.customData, null, 2);
            }
        },
        /** Creates and displays the list of file actions (preview, save, etc.). @param {object[]} files - The array of file entries from the header. */
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
        /** Creates a single folder item for the file actions list. @returns {HTMLDivElement} */
        createPackageFolderItem: (folderName, folderFiles) => {
            const item = document.createElement('div');
            item.className = 'file-item';
            const totalSize = folderFiles.reduce((sum, f) => sum + f.length, 0);
            const fileNamesJson = Utils.escapeHtml(JSON.stringify(folderFiles.map(f => f.name)));
            const isLocked = state.currentMasterHeader?.encryption && !state.isContentUnlocked;
            const icon = isLocked ? '🔒' : '📁';
            const displayName = isLocked ? Utils.censorFilename(folderName) : Utils.escapeHtml(folderName);

            item.innerHTML = `<div class="file-icon">${icon}</div>
                <div class="file-meta"><div class="file-name" title="${displayName}">${displayName}</div><div class="file-size">${Utils.humanSize(totalSize)} (${folderFiles.length} items)</div></div>
                <div style="display: flex; gap: 5px;"><button class="btn btn-small btn-primary" data-action="save-folder" data-folder-name="${Utils.escapeHtml(folderName)}" data-files-json='${fileNamesJson}'>💾 ZIP</button></div>`;
            return item;
        },
        /** Creates a single file item for the file actions list. @returns {HTMLDivElement} */
        createPackageFileItem: (fileEntry, index) => {
            const item = document.createElement('div');
            item.className = 'file-item';
            const canPreview = Object.values(CONFIG.SUPPORTED_PREVIEW_TYPES).flat().includes(fileEntry.mime);
            const isLocked = state.currentMasterHeader?.encryption && !state.isContentUnlocked;
            const displayName = isLocked ? Utils.censorFilename(fileEntry.name) : Utils.escapeHtml(fileEntry.name);
            
            item.innerHTML = `<div class="file-icon">${UI.getFileIcon(fileEntry.mime)}</div>
                <div class="file-meta"><div class="file-name" title="${displayName}">${displayName}</div><div class="file-size">${Utils.humanSize(fileEntry.length)} - <em>${fileEntry.mime || 'unknown'}</em></div></div>
                <div style="display: flex; gap: 5px;">
                    ${canPreview ? `<button class="btn btn-small btn-secondary" data-action="preview" data-index="${index}">👁️ Preview</button>` : ''}
                    <button class="btn btn-small btn-primary" data-action="save" data-index="${index}">💾 Save</button>
                </div>`;
            return item;
        },
        /** Refreshes the file list view, typically after unlocking content. */
        refreshFileListView: () => {
            elements.pkgInfo.querySelector('.file-list')?.remove();
            Importer.createFileActionsList(state.currentMasterHeader.files);
        },
        /** Renders a preview of a file. @param {Blob} blob - The file content blob. @param {object} fileEntry - The file's header entry. */
        displayPreview: async (blob, fileEntry) => {
            Importer.clearPreview();
            const wrapper = Object.assign(document.createElement('div'), { className: 'preview-wrapper' });
            const previewer = Importer.getPreviewerForMime(fileEntry.mime);
            await previewer(blob, wrapper);
            elements.previewContent.appendChild(wrapper);
            elements.previewHeader.classList.remove(CONFIG.CLASSES.hidden);
        },
        /** Gets the appropriate preview rendering function for a MIME type. @param {string} mime - The MIME type. @returns {Function} */
        getPreviewerForMime: mime => {
            if (CONFIG.SUPPORTED_PREVIEW_TYPES.archive.includes(mime)) return Importer.previewArchive;
            if (mime.startsWith('image/')) return Importer.previewMedia('img');
            if (mime.startsWith('video/')) return Importer.previewMedia('video');
            if (mime.startsWith('audio/')) return Importer.previewMedia('audio');
            if (CONFIG.SUPPORTED_PREVIEW_TYPES.text.includes(mime)) return Importer.previewText;
            return Importer.previewFallback;
        },
        /** Previews a zip archive by listing its contents. @param {Blob} blob - Zip file blob. @param {HTMLElement} wrapper - The container element. */
        previewArchive: async (blob, wrapper) => {
            try {
                const zip = await JSZip.loadAsync(blob);
                wrapper.innerHTML = `<div class="zip-preview-list"><ul>${Object.values(zip.files).map(f => `<li class="${f.dir ? 'is-dir' : ''}">${Utils.escapeHtml(f.name)}</li>`).join('')}</ul></div>`;
            } catch (e) { Importer.previewFallback(blob, wrapper); }
        },
        /** Previews media (image, video, audio). @param {'img'|'video'|'audio'} type - The type of media element to create. @returns {Function} */
        previewMedia: type => async (blob, wrapper) => {
            state.activePreviewUrl = URL.createObjectURL(blob);
            const el = Object.assign(document.createElement(type), { src: state.activePreviewUrl });
            if (type !== 'img') el.controls = true;
            wrapper.appendChild(el);
        },
        /** Previews a text-based file. @param {Blob} blob - Text file blob. @param {HTMLElement} wrapper - The container element. */
        previewText: async (blob, wrapper) => {
            wrapper.innerHTML = `<pre>${Utils.escapeHtml(await blob.text())}</pre>`;
        },
        /** Displays a fallback message for unsupported preview types. @param {Blob} blob - The blob. @param {HTMLElement} wrapper - The container element. */
        previewFallback: (blob, wrapper) => {
            wrapper.innerHTML = `<p>Preview not available for this file type.</p>`;
        },
        /** Clears the current file preview. */
        clearPreview: () => {
            if (state.activePreviewUrl) { URL.revokeObjectURL(state.activePreviewUrl); state.activePreviewUrl = null; }
            elements.previewContent.innerHTML = '';
            elements.previewHeader.classList.add(CONFIG.CLASSES.hidden);
        },
        /** Main handler for importing package files. @param {FileList} packageFiles - Files from an input or drop event. */
        handleImport: async (packageFiles) => {
            if (!packageFiles || packageFiles.length === 0) return;
            elements.pkgInfo.innerHTML = '';
            elements.importPasswordPrompt.classList.add(CONFIG.CLASSES.hidden);
            elements.customData.classList.add(CONFIG.CLASSES.hidden);
            state.currentEncryptionKey = null;
            state.isContentUnlocked = false;
            Importer.clearPreview();
            try {
                const headers = await Promise.all([...packageFiles].map(Importer.readPackageHeader));
                const { masterHeader, sortedShards } = Importer.processHeaders(headers);
                state.currentMasterHeader = masterHeader;
                state.currentImportedShards = sortedShards;
                const totalSize = sortedShards.reduce((s, sh) => s + sh.packageFile.size, 0);
                Importer.displayPackageInfo(masterHeader, totalSize);
                Importer.createFileActionsList(masterHeader.files);

                if (masterHeader.encryption) {
                    elements.importPasswordPrompt.classList.remove(CONFIG.CLASSES.hidden);
                    UI.showToast('Package is encrypted. Enter password to access files.', 'info');
                }

                UI.showToast(`Package loaded: ${masterHeader.files.length} files`, 'success');
            } catch (e) { UI.showToast(`Import failed: ${e.message}`, 'error'); console.error(e); }
        },
        /** Handles the 'Unlock' button click for encrypted content. */
        handleUnlockContent: async () => {
            const password = elements.importPasswordInput.value;
            if (!password || !state.currentMasterHeader?.encryption) return;

            UI.showToast('Verifying password...', 'info');
            try {
                const salt = new Uint8Array(state.currentMasterHeader.encryption.salt);
                const key = await Utils.deriveKeyFromPassword(password, salt);
                state.currentEncryptionKey = key;
                
                // Test decryption on the first file to validate the password
                const firstFile = state.currentMasterHeader.files[0];
                if (firstFile) {
                    await Importer.extractFileBlob(firstFile);
                }
                
                state.isContentUnlocked = true;
                UI.showToast('Password correct! Content unlocked.', 'success');
                Importer.refreshFileListView();
                elements.importPasswordPrompt.classList.add(CONFIG.CLASSES.hidden);
                elements.importPasswordInput.value = '';

                elements.pkgInfo.querySelector('[data-action="view-custom-data"]')?.classList.remove(CONFIG.CLASSES.hidden);

                if (state.pendingFileAction) {
                    App.handleFileAction(state.pendingFileAction.event, true);
                    state.pendingFileAction = null;
                }
            } catch (e) {
                state.currentEncryptionKey = null;
                state.isContentUnlocked = false;
                UI.showToast(e.message || 'Incorrect password or corrupted file.', 'error');
                console.error(e);
            }
        },
    };

    // --- Editor Module (Metadata Editing Logic) ---
    const Editor = {
        /** Unlocks the editing form after successful key verification. @param {object} header - The package master header. */
        unlockForm: (header) => {
            state.isEditorUnlocked = true;
            elements.editKeyVerification.classList.add(CONFIG.CLASSES.hidden);
            elements.editForm.dataset.locked = "false";
            elements.masterKey.value = '';
            Editor.displayMetadataForm(header);
        },
        /** Populates the metadata form with data from the package header. @param {object} header - The package master header. */
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
        /** Main handler for loading a package into the editor view. @param {FileList} packageFiles - The package files. */
        handleLoad: async (packageFiles) => {
            if (!packageFiles || packageFiles.length === 0) return;
            Editor.clear();
            try {
                const loadedShards = await Promise.all([...packageFiles].map(Importer.readPackageHeader));
                const { masterHeader, sortedShards } = Importer.processHeaders(loadedShards);
                state.shardsForEditing = sortedShards;
                state.currentMasterHeader = masterHeader;
                elements.editForm.classList.remove(CONFIG.CLASSES.hidden);
                if (masterHeader.keyHash) {
                    elements.editKeyVerification.classList.remove(CONFIG.CLASSES.hidden);
                    elements.editForm.dataset.locked = "true";
                    state.isEditorUnlocked = false;
                } else { Editor.unlockForm(masterHeader); }
                UI.showToast(`Loaded "${masterHeader.packageName || 'package'}" for editing.`, 'success');
            } catch (e) { UI.showToast(`Failed to load package: ${e.message}`, 'error'); console.error(e); Editor.clear(); }
        },
        /** Handles the 'Verify Key' button click. */
        handleVerifyKey: async () => {
            const key = elements.masterKey.value;
            if (!key || !state.currentMasterHeader?.keyHash) return;
            if (await Utils.computeStringSHA256(key) === state.currentMasterHeader.keyHash) {
                UI.showToast('Key correct! Unlocking editor.', 'success');
                Editor.unlockForm(state.currentMasterHeader);
            } else { UI.showToast('Incorrect master key.', 'error'); }
        },
        /** Handles the 'Save Changes' button click. */
        handleSaveChanges: async () => {
            if (state.isConfiguring) {
                try {
                    state.pendingMetadata = Editor._getNewMetadataFromForm();
                    UI.showToast('Metadata configured successfully!', 'success');
                    App.returnToCreateView();
                } catch (e) {
                    UI.showToast(e.message, 'error');
                }
                return;
            }

            if (!state.isEditorUnlocked) return UI.showToast('Unlock the package with the master key first.', 'warning');
            if (state.isProcessing) return;

            state.isProcessing = true;
            UI.toggleProgress(true, 'Preparing to rebuild package...');
            elements.editDownload.innerHTML = '';

            try {
                const newGlobalMetadata = Editor._getNewMetadataFromForm();
                const oldPassword = elements.editOldPassword.value;
                const newPassword = elements.editNewPassword.value;
                
                if (oldPassword || newPassword) {
                    await Editor._rebuildPackageWithEncryptionChanges(newGlobalMetadata, oldPassword, newPassword);
                } else {
                    await Editor._updatePackageMetadataOnly(newGlobalMetadata);
                }
            } catch (e) { UI.showToast(`Error saving package: ${e.message}`, 'error'); console.error(e); }
            finally { 
                state.isProcessing = false; 
                setTimeout(() => UI.toggleProgress(false), 1500);
            }
        },
        /** Helper to gather metadata from the edit form. @returns {object} */
        _getNewMetadataFromForm: () => {
            let customData = null;
            if (elements.pkgCustomData.value.trim()) {
               try { customData = JSON.parse(elements.pkgCustomData.value.trim()); } 
               catch (e) { throw new Error("Custom JSON data is invalid."); }
            }
            return {
                packageName: elements.pkgName.value.trim(), author: elements.pkgAuthor.value.trim(), description: elements.pkgDescription.value.trim(),
                source: elements.pkgSource.value.trim(), tags: elements.pkgTags.value.split(',').map(t => t.trim()).filter(Boolean),
                version: parseInt(elements.pkgVersion.value, 10) || CONFIG.CURRENT_VERSION, created: new Date(elements.pkgCreated.value).getTime() || Date.now(), customData
            };
        },
        /** Helper for when only metadata is changed, not encryption. @param {object} newGlobalMetadata - The new metadata object. */
        _updatePackageMetadataOnly: async (newGlobalMetadata) => {
            UI.updateProgress(50, "Applying new metadata...");
            const editedShards = await Promise.all(state.shardsForEditing.map(async (shard) => {
                const newHeader = { ...shard.header, ...newGlobalMetadata };
                const payload = shard.packageFile.slice(shard.payloadStart);
                const baseName = shard.packageFile.name.replace(/\.nyx$/, '');
                return await Packer.buildBlob(newHeader, [payload], `${baseName}-edited`);
            }));
            UI.renderDownloadArea(editedShards, elements.editDownload);
            UI.showToast('Package metadata saved successfully!', 'success');
        },
        /** Helper for when encryption is added, changed, or removed. @param {object} newGlobalMetadata - The new metadata object. @param {string} oldPassword - The old password. @param {string} newPassword - The new password. */
        _rebuildPackageWithEncryptionChanges: async (newGlobalMetadata, oldPassword, newPassword) => {
            const wasEncrypted = !!state.currentMasterHeader.encryption;
            if (wasEncrypted && !oldPassword) {
                throw new Error("Old password is required to change or remove encryption.");
            }
            
            let oldKey = null;
            if (wasEncrypted) {
                UI.updateProgress(5, "Verifying old password...");
                oldKey = await Utils.deriveKeyFromPassword(oldPassword, new Uint8Array(state.currentMasterHeader.encryption.salt));
            }
            
            const newBaseHeader = { ...state.currentMasterHeader, ...newGlobalMetadata };
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
            for (let i = 0; i < state.currentMasterHeader.files.length; i++) {
                const fileEntry = state.currentMasterHeader.files[i];
                UI.updateProgress(15 + (i / state.currentMasterHeader.files.length) * 65, `Processing file ${i + 1}...`);
                let currentBlob = await Importer._extractRawFileBlob(fileEntry, state.shardsForEditing);
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
            const originalTotalSize = state.shardsForEditing.reduce((sum, s) => sum + s.packageFile.size, 0);
            const originalSplitSize = state.shardsForEditing.length > 1 ? originalTotalSize / state.shardsForEditing.length : 0;
            await Packer.buildFromPayloads(newBaseHeader, finalPayloads, originalSplitSize, elements.progress, elements.editDownload);
            UI.showToast('Package rebuilt and saved successfully!', 'success');
        },
        /** Clears the editor view and resets its state. */
        clear: () => {
            if (state.isConfiguring) {
                App.returnToCreateView();
                return;
            }
            state.shardsForEditing = []; state.currentMasterHeader = null; state.isEditorUnlocked = false;
            elements.metadata.reset();
            elements.editForm.classList.add(CONFIG.CLASSES.hidden);
            elements.editKeyVerification.classList.add(CONFIG.CLASSES.hidden);
            elements.editDownload.innerHTML = '';
            if (elements.editInput) elements.editInput.value = '';
            UI.showToast('Editor cleared.', 'info');
        },
    };

    // --- App Controller & Event Handlers ---
    const App = {
        /** Initializes the application. */
        init() {
            App.setupEventListeners();
            App.setupDragAndDrop();
            App.loadShardsFromUrl();
            UI.showToast('Application ready!', 'success');
            UI.updateCreateViewState();
        },
        /** Loads shards specified in the URL query parameters. */
        loadShardsFromUrl: async () => {
            const shardUrls = new URLSearchParams(window.location.search).getAll('shard');
            if (shardUrls.length === 0) return;
            App.switchToView('import');
            UI.showToast(`Importing ${shardUrls.length} shard(s) from URL...`, 'info');
            try {
                const files = await Promise.all(shardUrls.map(async (url) => {
                    if (!url.startsWith('http')) throw new Error(`Invalid URL: ${url.slice(0, 30)}...`);
                    const res = await fetch(url);
                    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.statusText}`);
                    const blob = await res.blob();
                    const filename = new URL(url).pathname.split('/').pop() || 'shard.nyx';
                    return new File([blob], filename, { type: 'application/octet-stream' });
                }));
                await Importer.handleImport(files);
            } catch (e) { UI.showToast(`Error loading from URL: ${e.message}`, 'error'); console.error(e); }
        },
        /** Switches the visible view. @param {'create'|'import'|'edit'} viewName - The name of the view to switch to. */
        switchToView: (viewName) => {
            const currentView = document.querySelector('.active-view');
            if (currentView && currentView.id === 'edit-view' && state.isConfiguring && viewName !== 'edit') {
                 App.returnToCreateView(false); // don't switch view again
            }

            // Hide all views
            Object.values(CONFIG.SELECTORS.views).forEach(selector => {
                document.querySelector(selector)?.classList.remove(CONFIG.CLASSES.activeView);
            });

            // Deactivate all switcher buttons
            Object.keys(CONFIG.SELECTORS.buttons).forEach(buttonKey => {
                if (buttonKey.startsWith('switchTo')) {
                    elements[buttonKey]?.classList.remove(CONFIG.CLASSES.activeBtn);
                }
            });

            // Activate the target view using the new unique key
            const viewKey = `${viewName}View`; // e.g., 'create' -> 'createView'
            elements[viewKey]?.classList.add(CONFIG.CLASSES.activeView);
            
            // Activate the target button
            const buttonKey = `switchTo${viewName.charAt(0).toUpperCase() + viewName.slice(1)}`;
            elements[buttonKey]?.classList.add(CONFIG.CLASSES.activeBtn);
        },
        /** Adds new files to the creation list, avoiding duplicates. @param {{file: File, fullPath: string}[]} newFileObjects - Array of new file objects. */
        addFiles: (newFileObjects) => {
            const existingPaths = new Set(state.files.map(f => f.fullPath));
            const validFiles = newFileObjects.filter(fObj => {
                const alreadyExists = existingPaths.has(fObj.fullPath);
                if (alreadyExists) UI.showToast(`File "${fObj.fullPath}" already added`, 'warning');
                return !alreadyExists;
            });
            if (validFiles.length > 0) {
                state.files.push(...validFiles);
                UI.showToast(`Added ${validFiles.length} file${validFiles.length === 1 ? '' : 's'}`, 'success');
                UI.updateCreateViewState();
            }
        },
        /** Clears all files from the creation list. */
        clearFiles: () => {
            if (state.files.length === 0) return;
            state.files = [];
            state.pendingMetadata = null;
            elements.download.innerHTML = '';
            elements.masterKeyArea.classList.add(CONFIG.CLASSES.hidden);
            UI.showToast('All files cleared', 'success');
            UI.updateCreateViewState();
        },
        /** Recursively traverses a dropped file system entry (file or directory). @param {FileSystemEntry} entry - The entry to traverse. @returns {Promise<{file: File, fullPath: string}[]>} A flat list of file objects. */
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
        /** Creates and downloads a zip archive from a list of package file entries. @param {object[]} fileEntries - The file entries from the master header. @param {string} zipName - The desired name for the zip file. */
        createZipFromEntries: async (fileEntries, zipName) => {
            if (state.isProcessing) return;
            state.isProcessing = true;
            try {
                if (state.currentMasterHeader.encryption && !state.isContentUnlocked) {
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
            finally { state.isProcessing = false; }
        },
        /** Handles delegated click events for file actions in the import view. @param {Event} event - The click event. @param {boolean} [force=false] - Whether to bypass the encryption check (used after password entry). */
        handleFileAction: async (event, force = false) => {
            const button = event.target.closest('button[data-action]');
            if (!button) return;

            const { action, index, folderName, filesJson } = button.dataset;

            if (action === 'view-custom-data') {
                elements.customData.classList.toggle(CONFIG.CLASSES.hidden);
                return;
            }

            if (state.currentMasterHeader?.encryption && !state.isContentUnlocked && !force) {
                UI.showToast('Password needed to access file content.', 'warning');
                elements.importPasswordPrompt.classList.remove(CONFIG.CLASSES.hidden);
                state.pendingFileAction = { event };
                return;
            }

            const fileEntry = state.currentMasterHeader?.files[parseInt(index, 10)];
            try {
                if (action === 'preview' && fileEntry) {
                    await Importer.displayPreview(await Importer.extractFileBlob(fileEntry), fileEntry);
                } else if (action === 'save' && fileEntry) {
                    Utils.downloadBlob(await Importer.extractFileBlob(fileEntry), fileEntry.name.split('/').pop());
                } else if (action === 'save-folder') {
                    UI.showToast(`Creating zip for "${folderName}"...`, 'info');
                    const entries = JSON.parse(filesJson).map(name => state.currentMasterHeader.files.find(f => f.name === name)).filter(Boolean);
                    await App.createZipFromEntries(entries, `${folderName}.zip`);
                } else if (action === 'save-all-zip') {
                    UI.showToast('Creating full package zip...', 'info');
                    await App.createZipFromEntries(state.currentMasterHeader.files, `package-all-files.zip`);
                }
            } catch (e) { UI.showToast(`${action} failed: ${e.message}`, 'error'); console.error(e); }
        },
        /** Handles click on the 'Configure Metadata' button */
        handleConfigureMetadata: () => {
            if (state.files.length === 0) {
                UI.showToast('Please add files before configuring metadata.', 'warning');
                return;
            }
            state.isConfiguring = true;
            const tempHeader = state.pendingMetadata || { created: Date.now() };
            
            Editor.displayMetadataForm(tempHeader);
            
            // Configure Edit view for metadata entry
            elements.editZone.parentElement.classList.add(CONFIG.CLASSES.hidden);
            elements.editKeyVerification.classList.add(CONFIG.CLASSES.hidden);
            elements.editDownload.classList.add(CONFIG.CLASSES.hidden);
            elements.editEncryptionSection.classList.add(CONFIG.CLASSES.hidden);
            elements.editForm.classList.remove(CONFIG.CLASSES.hidden);
            elements.editForm.dataset.locked = "false";
            elements.saveChanges.innerHTML = `<span aria-hidden="true">✅</span> Confirm Metadata`;
            
            App.switchToView('edit');
        },
        /** Resets the edit view from configuration mode and returns to create view */
        returnToCreateView: (switchView = true) => {
            state.isConfiguring = false;
            
            // Reset Edit view UI
            elements.editZone.parentElement.classList.remove(CONFIG.CLASSES.hidden);
            elements.editDownload.classList.remove(CONFIG.CLASSES.hidden);
            elements.editForm.classList.add(CONFIG.CLASSES.hidden);
            elements.saveChanges.innerHTML = `<span aria-hidden="true">💾</span> Save Changes`;
            
            if (switchView) {
                App.switchToView('create');
            }
        },
        /** Sets up all the application's event listeners. */
        setupEventListeners: () => {
            // View Switching
            elements.switchToCreate.addEventListener('click', () => App.switchToView('create'));
            elements.switchToImport.addEventListener('click', () => App.switchToView('import'));
            elements.switchToEdit.addEventListener('click', () => App.switchToView('edit'));
            // File Inputs via click
            elements.uploadZone.addEventListener('click', () => elements.fileInput.click());
            elements.importZone.addEventListener('click', () => elements.importInput.click());
            elements.editZone.addEventListener('click', () => elements.editInput.click());
            // File Inputs via change event
            elements.fileInput.addEventListener('change', e => { App.addFiles([...e.target.files].map(f => ({ file: f, fullPath: f.name }))); e.target.value = ''; });
            elements.importInput.addEventListener('change', e => { App.switchToView('import'); Importer.handleImport(e.target.files); e.target.value = ''; });
            elements.editInput.addEventListener('change', e => { App.switchToView('edit'); Editor.handleLoad(e.target.files); e.target.value = ''; });
            
            // Create View
            elements.create.addEventListener('click', Packer.handleCreate);
            elements.clear.addEventListener('click', App.clearFiles);
            elements.copyKey.addEventListener('click', () => { navigator.clipboard.writeText(elements.masterKeyOutput.value); UI.showToast('Master key copied!', 'success'); });
            elements.splitSize.addEventListener('input', UI.updateCreateViewState);
            elements.configureMetadata.addEventListener('click', App.handleConfigureMetadata);
            elements.fileList.addEventListener('click', (e) => {
                const button = e.target.closest('button[data-action="remove"]');
                if (button) {
                    const index = parseInt(button.dataset.index, 10);
                    if (!isNaN(index) && state.files[index]) {
                        const [removed] = state.files.splice(index, 1);
                        UI.updateCreateViewState(); UI.showToast(`Removed "${removed.fullPath}"`, 'success');
                    }
                }
            });
            // Import View
            elements.clearPreview.addEventListener('click', Importer.clearPreview);
            elements.pkgInfo.addEventListener('click', App.handleFileAction);
            elements.unlockContent.addEventListener('click', Importer.handleUnlockContent);
            // Edit View
            elements.saveChanges.addEventListener('click', Editor.handleSaveChanges);
            elements.clearEdit.addEventListener('click', Editor.clear);
            elements.verifyKey.addEventListener('click', Editor.handleVerifyKey);
        },
        /** Sets up drag and drop functionality for all drop zones. */
        setupDragAndDrop: () => {
            const setupZone = (zone, onDrop) => {
                if (!zone) return;
                ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evName => {
                    zone.addEventListener(evName, e => { e.preventDefault(); e.stopPropagation(); });
                });
                ['dragenter', 'dragover'].forEach(evName => {
                    zone.addEventListener(evName, () => zone.classList.add(CONFIG.CLASSES.dragover));
                });
                ['dragleave', 'drop'].forEach(evName => {
                    zone.addEventListener(evName, () => zone.classList.remove(CONFIG.CLASSES.dragover));
                });
                zone.addEventListener('drop', onDrop);
            };

            setupZone(elements.uploadZone, async (e) => {
                if (state.isProcessing) return;
                state.isProcessing = true;
                UI.updateCreateViewState();
                UI.showToast('Processing dropped items...', 'info');
                try {
                    const dataTransferItems = [...e.dataTransfer.items];
                    const fileTreePromises = dataTransferItems.map(item => App.traverseFileTree(item.webkitGetAsEntry()));
                    const files = (await Promise.all(fileTreePromises)).flat();
                    App.addFiles(files);
                } catch (err) { UI.showToast('Could not process dropped items.', 'error'); console.error(err); }
                finally { state.isProcessing = false; UI.updateCreateViewState(); }
            });
            setupZone(elements.importZone, (e) => { App.switchToView('import'); Importer.handleImport(e.dataTransfer.files); });
            setupZone(elements.editZone, (e) => { App.switchToView('edit'); Editor.handleLoad(e.dataTransfer.files); });
        },
    };

    // --- Initialize Application ---
    App.init();
});