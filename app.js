document.addEventListener('DOMContentLoaded', () => {

    // --- Configuration and Constants ---
    const CONFIG = {
        MAGIC: new TextEncoder().encode('NYXPKG1 '), // 8-byte package identifier
        CURRENT_VERSION: 3, // Version 3 introduced keyHash for protection
        SELECTORS: {
            views: { createView: '#create-view', importView: '#import-view', editView: '#edit-view' },
            buttons: {
                switchToCreate: '#switchToCreate', switchToImport: '#switchToImport', switchToEdit: '#switchToEdit',
                create: '#createBtn', clear: '#clearBtn', copyKey: '#copyKeyBtn', clearPreview: '#clearPreviewBtn',
                verifyKey: '#verifyKeyBtn', saveChanges: '#saveChangesBtn', clearEdit: '#clearEditBtn',
            },
            inputs: {
                file: '#fileInput', import: '#importInput', edit: '#editInput', splitSize: '#splitSize',
                masterKey: '#masterKeyInput',
            },
            zones: { upload: '#uploadZone', import: '#importZone', edit: '#editZone' },
            displays: {
                fileList: '#fileList', shardInfo: '#shardInfo', totalSizeInfo: '#totalSizeInfo',
                progress: '#createProgress', progressFill: '#progressFill', progressText: '#progressText',
                masterKeyArea: '#masterKeyArea', masterKeyOutput: '#masterKeyOutput', pkgInfo: '#pkgInfo',
                previewHeader: '#previewHeader', previewContent: '#previewContent',
            },
            containers: {
                download: '#downloadArea', editDownload: '#editDownloadArea',
                editForm: '#editFormContainer', editKeyVerification: '#editKeyVerification', toast: '#toastContainer',
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
    };

    // --- DOM Element Cache ---
    const elements = Object.values(CONFIG.SELECTORS).reduce((acc, group) => {
        Object.entries(group).forEach(([key, selector]) => { acc[key] = document.querySelector(selector); });
        return acc;
    }, {});

    // --- Utility Module ---
    const Utils = {
        humanSize: bytes => {
            if (bytes === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${units[i]}`;
        },
        escapeHtml: text => {
            if (typeof text !== 'string') text = String(text ?? '');
            return text.replace(/[&<>"']/g, match => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[match]));
        },
        downloadBlob: (blob, filename) => {
            const url = URL.createObjectURL(blob);
            const a = Object.assign(document.createElement('a'), { href: url, download: filename });
            document.body.appendChild(a).click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 60000);
        },
        bigIntTo8Bytes: n => {
            const buf = new ArrayBuffer(8);
            new DataView(buf).setBigUint64(0, BigInt(n), false);
            return new Uint8Array(buf);
        },
        readBigInt8Bytes: bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, false),
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
            const tzoffset = (new Date()).getTimezoneOffset() * 60000;
            return new Date(date - tzoffset).toISOString().slice(0, 16);
        },
    };

    // --- UI Module (Handles all DOM manipulations) ---
    const UI = {
        showToast: (message, type = 'info', duration = 4000) => {
            if (!elements.toast) return;
            const toast = Object.assign(document.createElement('div'), { className: `toast ${type}`, textContent: message, role: 'status', 'aria-live': 'polite' });
            elements.toast.appendChild(toast);
            setTimeout(() => toast.remove(), duration);
        },
        updateProgress: (percent, text) => {
            elements.progressFill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
            elements.progressFill.setAttribute('aria-valuenow', percent);
            if (text) elements.progressText.textContent = text;
        },
        toggleProgress: (show, text = 'Preparing...') => {
            elements.progress.classList.toggle(CONFIG.CLASSES.hidden, !show);
            if (show) UI.updateProgress(0, text);
        },
        getFileIcon: mimeType => {
            if (!mimeType) return '📄';
            if (mimeType.startsWith('image/')) return '🖼️';
            if (mimeType.startsWith('video/')) return '🎬';
            if (mimeType.startsWith('audio/')) return '🎵';
            if (mimeType.startsWith('text/')) return '📝';
            if (mimeType.includes('pdf')) return '📕';
            if (CONFIG.SUPPORTED_PREVIEW_TYPES.archive.includes(mimeType)) return '📦';
            return '📄';
        },
        renderFileList: () => {
            elements.fileList.innerHTML = '';
            const fragment = document.createDocumentFragment();
            state.files.forEach((fObj, index) => {
                const itemTemplate = elements.fileItem.content.cloneNode(true);
                const item = itemTemplate.querySelector('.file-item');
                item.querySelector('.file-icon').textContent = UI.getFileIcon(fObj.file.type);
                Object.assign(item.querySelector('.file-name'), { textContent: fObj.fullPath, title: fObj.fullPath });
                item.querySelector('.file-size').textContent = Utils.humanSize(fObj.file.size);
                item.querySelector('[data-action="remove"]').dataset.index = index;
                fragment.appendChild(itemTemplate);
            });
            elements.fileList.appendChild(fragment);
        },
        updateCreateViewState: () => {
            UI.renderFileList();
            elements.create.disabled = state.files.length === 0 || state.isProcessing;
            const totalSize = state.files.reduce((sum, f) => sum + f.file.size, 0);
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

            const allContainer = document.createElement('div');
            const linksContainer = document.createElement('div');
            linksContainer.className = 'download-links-container';

            files.forEach(file => {
                const url = URL.createObjectURL(file.blob);
                const link = Object.assign(document.createElement('a'), { href: url, download: file.filename, className: 'download-link' });
                link.innerHTML = `<strong>${Utils.escapeHtml(file.filename)}</strong> <small>(${Utils.humanSize(file.blob.size)})</small>`;
                linksContainer.appendChild(link);
                setTimeout(() => URL.revokeObjectURL(url), 300000);
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
                        Utils.downloadBlob(await zip.generateAsync({ type: "blob" }), `package-shards.zip`);
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
        buildBlob: async (headerObj, payloadBlobs, baseName) => {
            const headerBytes = new TextEncoder().encode(JSON.stringify(headerObj));
            const headerLenBuf = Utils.bigIntTo8Bytes(headerBytes.length);
            const blob = new Blob([CONFIG.MAGIC, headerLenBuf, headerBytes, ...payloadBlobs], { type: 'application/octet-stream' });
            const filename = `${baseName}-${new Date().toISOString().replace(/[:.]/g, '-')}.nyx`;
            return { blob, filename };
        },
        createFileEntries: () => state.files.map(({ file, fullPath }) => ({ name: fullPath, mime: file.type || 'application/octet-stream', length: file.size, lastModified: file.lastModified || Date.now() })),
        createSinglePackage: async (entries, baseHeader) => {
            UI.updateProgress(75, 'Building package header...');
            let offset = 0;
            const finalEntries = entries.map(e => ({ ...e, offset: (offset += e.length) - e.length }));
            const headerObj = { ...baseHeader, files: finalEntries, totalSize: offset };
            const builtPackage = await Packer.buildBlob(headerObj, state.files.map(f => f.file), 'package');
            UI.updateProgress(100, 'Finalizing...');
            UI.renderDownloadArea([builtPackage], elements.download);
            UI.showToast('Package created successfully!', 'success');
        },
        createSplitPackage: async (entries, splitSizeBytes, baseHeader) => {
            const shardData = [];
            const packageId = `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
            let shardNum = 1;
            let currentShard = { payload: [], entries: [], size: 0 };
            const totalPayloadSize = entries.reduce((sum, e) => sum + e.length, 0);
            const totalShardsEstimate = Math.max(1, Math.ceil(totalPayloadSize / splitSizeBytes));

            const finalizeCurrentShard = async () => {
                if (currentShard.payload.length === 0) return;
                const headerObj = { ...baseHeader, files: currentShard.entries, totalSize: currentShard.size, splitInfo: { id: packageId, shard: shardNum, total: totalShardsEstimate } };
                shardData.push(await Packer.buildBlob(headerObj, currentShard.payload, `package-shard${shardNum}`));
                shardNum++;
                currentShard = { payload: [], entries: [], size: 0 };
            };

            for (const entry of entries) {
                const file = state.files.find(f => f.fullPath === entry.name).file;
                let fileBytesProcessed = 0;
                while (fileBytesProcessed < entry.length) {
                    UI.updateProgress(75 + (shardNum / totalShardsEstimate) * 25, `Building shard ${shardNum}/${totalShardsEstimate}...`);
                    if (currentShard.size >= splitSizeBytes) await finalizeCurrentShard();
                    const spaceInShard = splitSizeBytes - currentShard.size;
                    const bytesToProcess = Math.min(entry.length - fileBytesProcessed, spaceInShard);
                    currentShard.payload.push(file.slice(fileBytesProcessed, fileBytesProcessed + bytesToProcess));
                    currentShard.entries.push({ name: entry.name, mime: entry.mime, length: bytesToProcess, offset: currentShard.size, lastModified: entry.lastModified, totalSize: entry.length });
                    currentShard.size += bytesToProcess;
                    fileBytesProcessed += bytesToProcess;
                }
            }
            await finalizeCurrentShard();
            UI.renderDownloadArea(shardData, elements.download);
            UI.showToast(`Package successfully split into ${shardNum - 1} shards.`, 'success');
        },
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
                const totalPayloadSize = entries.reduce((sum, e) => sum + e.length, 0);
                const splitSizeMB = parseFloat(elements.splitSize.value);
                const splitSizeBytes = !isNaN(splitSizeMB) && splitSizeMB > 0 ? splitSizeMB * 1024 * 1024 : 0;
                const baseHeader = { version: CONFIG.CURRENT_VERSION, created: Date.now(), keyHash };

                if (splitSizeBytes > 0 && totalPayloadSize > splitSizeBytes) await Packer.createSplitPackage(entries, splitSizeBytes, baseHeader);
                else await Packer.createSinglePackage(entries, baseHeader);

                elements.masterKeyOutput.value = masterKey;
                elements.masterKeyArea.classList.remove(CONFIG.CLASSES.hidden);
            } catch (e) { UI.showToast(`Package creation failed: ${e.message}`, 'error'); console.error(e); }
            finally {
                state.isProcessing = false;
                UI.updateCreateViewState();
                setTimeout(() => UI.toggleProgress(false), 1000);
            }
        },
    };

    // --- Importer Module (File Extraction Logic) ---
    const Importer = {
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
        processHeaders: (headers) => {
            if (headers.length === 0) throw new Error("No valid package shards found.");
            const firstHeader = headers[0].header;
            if (!firstHeader.splitInfo) {
                if (headers.length > 1) throw new Error("Cannot import multiple non-split packages at once.");
                return { masterHeader: firstHeader, sortedShards: [headers[0]] };
            }
            const { id, total } = firstHeader.splitInfo;
            const relevantShards = headers.filter(h => h.header.splitInfo?.id === id);
            if (relevantShards.length < total) UI.showToast(`Incomplete package. Found ${relevantShards.length} of ${total} shards.`, 'warning');

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
        extractFileBlob: async (fileEntry) => {
            if (!fileEntry.chunks || fileEntry.chunks.length === 0) {
                const shard = state.currentImportedShards[0];
                return shard.packageFile.slice(shard.payloadStart + fileEntry.offset, shard.payloadStart + fileEntry.offset + fileEntry.length, fileEntry.mime);
            }
            const chunkBlobs = await Promise.all(fileEntry.chunks.map(chunk => {
                const shard = state.currentImportedShards.find(s => s.header.splitInfo.shard === chunk.shard);
                if (!shard) throw new Error(`Could not find shard #${chunk.shard} for file "${fileEntry.name}"`);
                return shard.packageFile.slice(shard.payloadStart + chunk.offset, shard.payloadStart + chunk.offset + chunk.length);
            }));
            return new Blob(chunkBlobs, { type: fileEntry.mime });
        },
        displayPackageInfo: (header, totalSize) => {
            const details = {
                'Author': header.author, 'Source': header.source, 'Files': header.files.length, 'Total Size': Utils.humanSize(totalSize),
                'Created': new Date(header.created || 0).toLocaleString(), 'Package Version': header.version || 1,
            };
            const detailsHtml = Object.entries(details).filter(([, v]) => v).map(([k, v]) => `<div><strong>${k}:</strong> ${Utils.escapeHtml(v)}</div>`).join('');
            const descriptionHtml = header.description ? `<p class="package-description">${Utils.escapeHtml(header.description)}</p>` : '';
            const tagsHtml = header.tags?.length ? `<div class="package-tags">${header.tags.map(tag => `<span class="tag">${Utils.escapeHtml(tag)}</span>`).join('')}</div>` : '';
            const shardInfo = state.currentImportedShards.length > 1 ? `<div><strong>Shards:</strong> ${state.currentImportedShards.length}</div>` : '';

            elements.pkgInfo.innerHTML = `
                <div class="package-summary">
                    <h3>📦 Package: <span class="pkg-name">${Utils.escapeHtml(header.packageName) || 'Untitled'}</span></h3>
                    ${descriptionHtml}${tagsHtml}
                    <div class="package-details-grid">${detailsHtml}${shardInfo}</div>
                    <div class="view-actions"><button class="btn btn-primary" data-action="save-all-zip">💾 Download All as .zip</button></div>
                </div>`;
        },
        createFileActionsList: (files) => {
            const listContainer = document.createElement('div');
            listContainer.className = 'file-list';
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
            const item = document.createElement('div');
            item.className = 'file-item';
            const totalSize = folderFiles.reduce((sum, f) => sum + f.length, 0);
            const fileNamesJson = Utils.escapeHtml(JSON.stringify(folderFiles.map(f => f.name)));
            item.innerHTML = `<div class="file-icon">📁</div>
                <div class="file-meta"><div class="file-name">${Utils.escapeHtml(folderName)}</div><div class="file-size">${Utils.humanSize(totalSize)} (${folderFiles.length} items)</div></div>
                <div style="display: flex; gap: 5px;"><button class="btn btn-small btn-primary" data-action="save-folder" data-folder-name="${Utils.escapeHtml(folderName)}" data-files-json='${fileNamesJson}'>💾 ZIP</button></div>`;
            return item;
        },
        createPackageFileItem: (fileEntry, index) => {
            const item = document.createElement('div');
            item.className = 'file-item';
            const canPreview = Object.values(CONFIG.SUPPORTED_PREVIEW_TYPES).flat().includes(fileEntry.mime);
            item.innerHTML = `<div class="file-icon">${UI.getFileIcon(fileEntry.mime)}</div>
                <div class="file-meta"><div class="file-name">${Utils.escapeHtml(fileEntry.name)}</div><div class="file-size">${Utils.humanSize(fileEntry.length)} - <em>${fileEntry.mime}</em></div></div>
                <div style="display: flex; gap: 5px;">
                    ${canPreview ? `<button class="btn btn-small btn-secondary" data-action="preview" data-index="${index}">👁️ Preview</button>` : ''}
                    <button class="btn btn-small btn-primary" data-action="save" data-index="${index}">💾 Save</button>
                </div>`;
            return item;
        },
        displayPreview: async (blob, fileEntry) => {
            Importer.clearPreview();
            const wrapper = document.createElement('div');
            wrapper.className = 'preview-wrapper';
            const previewer = Importer.getPreviewerForMime(fileEntry.mime);
            await previewer(blob, wrapper);
            elements.previewContent.appendChild(wrapper);
            elements.previewHeader.classList.remove(CONFIG.CLASSES.hidden);
        },
        getPreviewerForMime: mime => {
            if (CONFIG.SUPPORTED_PREVIEW_TYPES.archive.includes(mime)) return Importer.previewArchive;
            if (mime.startsWith('image/')) return Importer.previewMedia('img');
            if (mime.startsWith('video/')) return Importer.previewMedia('video');
            if (mime.startsWith('audio/')) return Importer.previewMedia('audio');
            if (CONFIG.SUPPORTED_PREVIEW_TYPES.text.includes(mime)) return Importer.previewText;
            return Importer.previewFallback;
        },
        previewArchive: async (blob, wrapper) => {
            try {
                const zip = await JSZip.loadAsync(blob);
                wrapper.innerHTML = `<div class="zip-preview-list"><ul>${Object.values(zip.files).map(f => `<li class="${f.dir ? 'is-dir' : ''}">${Utils.escapeHtml(f.name)}</li>`).join('')}</ul></div>`;
            } catch (e) { Importer.previewFallback(blob, wrapper); }
        },
        previewMedia: type => async (blob, wrapper) => {
            state.activePreviewUrl = URL.createObjectURL(blob);
            const el = Object.assign(document.createElement(type), { src: state.activePreviewUrl });
            if (type !== 'img') el.controls = true;
            wrapper.appendChild(el);
        },
        previewText: async (blob, wrapper) => {
            wrapper.innerHTML = `<pre>${Utils.escapeHtml(await blob.text())}</pre>`;
        },
        previewFallback: (blob, wrapper) => {
            wrapper.innerHTML = `<p>Preview not available for this file type.</p>`;
        },
        clearPreview: () => {
            if (state.activePreviewUrl) { URL.revokeObjectURL(state.activePreviewUrl); state.activePreviewUrl = null; }
            elements.previewContent.innerHTML = '';
            elements.previewHeader.classList.add(CONFIG.CLASSES.hidden);
        },
        handleImport: async (packageFiles) => {
            if (!packageFiles || packageFiles.length === 0) return;
            elements.pkgInfo.innerHTML = '';
            Importer.clearPreview();
            try {
                const headers = await Promise.all([...packageFiles].map(Importer.readPackageHeader));
                const { masterHeader, sortedShards } = Importer.processHeaders(headers);
                state.currentMasterHeader = masterHeader;
                state.currentImportedShards = sortedShards;
                Importer.displayPackageInfo(masterHeader, sortedShards.reduce((s, sh) => s + sh.packageFile.size, 0));
                Importer.createFileActionsList(masterHeader.files);
                UI.showToast(`Package loaded: ${masterHeader.files.length} files`, 'success');
            } catch (e) { UI.showToast(`Import failed: ${e.message}`, 'error'); console.error(e); }
        },
    };

    // --- Editor Module (Metadata Editing Logic) ---
    const Editor = {
        unlockForm: (header) => {
            state.isEditorUnlocked = true;
            elements.editKeyVerification.classList.add(CONFIG.CLASSES.hidden);
            elements.editForm.dataset.locked = "false";
            elements.masterKey.value = '';
            Editor.displayMetadataForm(header);
        },
        displayMetadataForm: (h) => {
            elements.metadata.reset();
            elements.pkgName.value = h.packageName || '';
            elements.pkgAuthor.value = h.author || '';
            elements.pkgDescription.value = h.description || '';
            elements.pkgSource.value = h.source || '';
            elements.pkgTags.value = (h.tags || []).join(', ');
            elements.pkgVersion.value = h.version || 1;
            elements.pkgCreated.value = Utils.dateToLocalISO(new Date(h.created || Date.now()));
            elements.pkgCustomData.value = h.customData ? JSON.stringify(h.customData, null, 2) : '';
        },
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
        handleVerifyKey: async () => {
            const key = elements.masterKey.value;
            if (!key || !state.currentMasterHeader?.keyHash) return;
            if (await Utils.computeStringSHA256(key) === state.currentMasterHeader.keyHash) {
                UI.showToast('Key correct! Unlocking editor.', 'success');
                Editor.unlockForm(state.currentMasterHeader);
            } else { UI.showToast('Incorrect master key.', 'error'); }
        },
        handleSaveChanges: async () => {
            if (!state.isEditorUnlocked) return UI.showToast('Unlock the package with the master key first.', 'warning');
            if (state.isProcessing) return;
            state.isProcessing = true;
            UI.showToast('Rebuilding package with new metadata...', 'info');
            try {
                let customData = null;
                const customDataRaw = elements.pkgCustomData.value.trim();
                if (customDataRaw) {
                    try { customData = JSON.parse(customDataRaw); }
                    catch (e) { UI.showToast(`Warning: Custom JSON data is invalid and won't be saved. ${e.message}`, 'warning'); }
                }
                const newGlobalMetadata = {
                    packageName: elements.pkgName.value.trim(), author: elements.pkgAuthor.value.trim(), description: elements.pkgDescription.value.trim(),
                    source: elements.pkgSource.value.trim(), tags: elements.pkgTags.value.split(',').map(t => t.trim()).filter(Boolean),
                    version: parseInt(elements.pkgVersion.value, 10) || CONFIG.CURRENT_VERSION, created: new Date(elements.pkgCreated.value).getTime() || Date.now(), customData: customData,
                };
                const editedShards = await Promise.all(state.shardsForEditing.map(async (shard) => {
                    const newHeader = { ...shard.header, ...newGlobalMetadata };
                    const payload = shard.packageFile.slice(shard.payloadStart);
                    const baseName = shard.packageFile.name.replace(/\.nyx$/, '');
                    return await Packer.buildBlob(newHeader, [payload], `${baseName}-edited`);
                }));
                UI.renderDownloadArea(editedShards, elements.editDownload);
                UI.showToast('Package saved successfully!', 'success');
            } catch (e) { UI.showToast(`Error saving package: ${e.message}`, 'error'); console.error(e); }
            finally { state.isProcessing = false; }
        },
        clear: () => {
            state.shardsForEditing = []; state.currentMasterHeader = null; state.isEditorUnlocked = false;
            elements.metadata.reset();
            elements.editForm.classList.add(CONFIG.CLASSES.hidden);
            elements.editKeyVerification.classList.add(CONFIG.CLASSES.hidden);
            elements.editDownload.innerHTML = '';
            if (elements.edit) elements.edit.value = '';
            UI.showToast('Editor cleared.', 'info');
        },
    };

    // --- App Controller & Event Handlers ---
    const App = {
        init() {
            App.setupEventListeners();
            App.setupDragAndDrop();
            App.loadShardsFromUrl();
            UI.showToast('Application ready!', 'success');
            UI.updateCreateViewState();
        },
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
                    return new File([blob], new URL(url).pathname.split('/').pop() || 'shard.nyx', { type: 'application/octet-stream' });
                }));
                await Importer.handleImport(files);
            } catch (e) { UI.showToast(`Error loading from URL: ${e.message}`, 'error'); console.error(e); }
        },
        switchToView: (viewName) => {
            // Deactivate all views
            Object.keys(CONFIG.SELECTORS.views).forEach(viewKey => {
                elements[viewKey]?.classList.remove(CONFIG.CLASSES.activeView);
            });

            // Deactivate all switcher buttons
            Object.keys(CONFIG.SELECTORS.buttons).forEach(buttonKey => {
                if (buttonKey.startsWith('switchTo')) {
                    elements[buttonKey]?.classList.remove(CONFIG.CLASSES.activeBtn);
                }
            });

            // Activate the target view using the new unique key (e.g., 'createView')
            const viewKey = `${viewName}View`;
            elements[viewKey]?.classList.add(CONFIG.CLASSES.activeView);

            // Activate the target button
            const buttonKey = `switchTo${viewName.charAt(0).toUpperCase() + viewName.slice(1)}`;
            elements[buttonKey]?.classList.add(CONFIG.CLASSES.activeBtn);
        },
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
        clearFiles: () => {
            if (state.files.length === 0) return;
            state.files = [];
            elements.download.innerHTML = '';
            elements.masterKeyArea.classList.add(CONFIG.CLASSES.hidden);
            UI.showToast('All files cleared', 'success');
            UI.updateCreateViewState();
        },
        traverseFileTree: async (entry) => {
            if (!entry) return [];
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
            await processEntry(entry);
            return files;
        },
        createZipFromEntries: async (fileEntries, zipName) => {
            if (state.isProcessing) return;
            state.isProcessing = true;
            try {
                const zip = new JSZip();
                for (const fileEntry of fileEntries) {
                    zip.file(fileEntry.name, await Importer.extractFileBlob(fileEntry));
                }
                Utils.downloadBlob(await zip.generateAsync({ type: "blob" }), zipName);
            } catch (e) { UI.showToast(`Failed to create zip: ${e.message}`, 'error'); console.error(e); }
            finally { state.isProcessing = false; }
        },
        handleFileAction: async (e) => {
            const button = e.target.closest('button[data-action]');
            if (!button) return;
            const { action, index, folderName, filesJson } = button.dataset;
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
        setupEventListeners: () => {
            // View Switching
            elements.switchToCreate.addEventListener('click', () => App.switchToView('create'));
            elements.switchToImport.addEventListener('click', () => App.switchToView('import'));
            elements.switchToEdit.addEventListener('click', () => App.switchToView('edit'));
            // File Inputs
            elements.file.addEventListener('change', e => { App.addFiles([...e.target.files].map(f => ({ file: f, fullPath: f.name }))); e.target.value = ''; });
            elements.import.addEventListener('change', e => { App.switchToView('import'); Importer.handleImport(e.target.files); e.target.value = ''; });
            elements.edit.addEventListener('change', e => { App.switchToView('edit'); Editor.handleLoad(e.target.files); e.target.value = ''; });
            // Clickable Zones
            elements.upload.addEventListener('click', () => elements.file.click());
            elements.import.addEventListener('click', () => elements.import.click());
            elements.edit.addEventListener('click', () => elements.edit.click());
            // Create View
            elements.create.addEventListener('click', Packer.handleCreate);
            elements.clear.addEventListener('click', App.clearFiles);
            elements.copyKey.addEventListener('click', () => { navigator.clipboard.writeText(elements.masterKeyOutput.value); UI.showToast('Master key copied!', 'success'); });
            elements.splitSize.addEventListener('input', UI.updateCreateViewState);
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
            // Edit View
            elements.saveChanges.addEventListener('click', Editor.handleSaveChanges);
            elements.clearEdit.addEventListener('click', Editor.clear);
            elements.verifyKey.addEventListener('click', Editor.handleVerifyKey);
        },
        setupDragAndDrop: () => {
            const setupZone = (zone, onDrop) => {
                ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(ev => zone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); }));
                ['dragenter', 'dragover'].forEach(ev => zone.addEventListener(ev, () => zone.classList.add(CONFIG.CLASSES.dragover)));
                ['dragleave', 'drop'].forEach(ev => zone.addEventListener(ev, () => zone.classList.remove(CONFIG.CLASSES.dragover)));
                zone.addEventListener('drop', onDrop);
            };
            setupZone(elements.upload, async (e) => {
                if (state.isProcessing) return;
                state.isProcessing = true;
                UI.updateCreateViewState();
                UI.showToast('Processing dropped items...', 'info');
                try {
                    const files = (await Promise.all([...e.dataTransfer.items].map(i => App.traverseFileTree(i.webkitGetAsEntry())))).flat();
                    App.addFiles(files);
                } catch (err) { UI.showToast('Could not process dropped items.', 'error'); console.error(err); }
                finally { state.isProcessing = false; UI.updateCreateViewState(); }
            });
            setupZone(elements.import, (e) => { App.switchToView('import'); Importer.handleImport(e.dataTransfer.files); });
            setupZone(elements.edit, (e) => { App.switchToView('edit'); Editor.handleLoad(e.dataTransfer.files); });
        },
    };

    // --- Initialize Application ---
    App.init();
});