document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    //=================================================================================
    //  IMPORTER MODULE
    //=================================================================================
    Object.assign(Importer, {
        // Renders the package metadata and summary information
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
            
            if (header.encryption) {
                elements.pkgInfo.appendChild(elements.importPasswordPrompt);
                elements.importPasswordPrompt.classList.remove(CONFIG.CLASSES.hidden);
                UI.showToast('Package is encrypted. Enter password to access files.', 'info');
            }
            
            if(header.customData) elements.customDataContent.textContent = JSON.stringify(header.customData, null, 2);
        },

        // Renders the list of files within an imported package
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

        // Creates a DOM element for a folder in the imported file list
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

        // Creates a DOM element for a single file in the imported file list
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

        // Refreshes the file list view, typically after unlocking content
        refreshFileListView: () => {
            const { currentMasterHeader } = State.getState();
            elements.pkgInfo.querySelector('.file-list')?.remove();
            if (currentMasterHeader) {
                Importer.createFileActionsList(currentMasterHeader.files);
            }
        },

        // Displays an inline preview for a file
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

        // Returns the appropriate preview handler function for a given MIME type
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
    });
    
    // Extend the App module with import-specific handlers
    Object.assign(App, {
        // Handles the import of one or more .nyx files
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
                
                // --- CHANGE: The logic that was here has been moved to displayPackageInfo ---
                
                UI.showToast(`Package loaded: ${masterHeader.files.length} files`, 'success');
            } catch (e) {
                UI.showToast(`Import failed: ${e.message}`, 'error');
                console.error(e);
            } finally {
                importToast?.remove();
            }
        },

        // Handles the 'Unlock' button click for encrypted packages
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

        // Handles clicks on file action buttons (preview, save, etc.)
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
    });

    // Encapsulated setup function for this view
    function setupImportViewEventListeners() {
        elements.importZone.addEventListener('click', () => elements.importInput.click());
        elements.importInput.addEventListener('change', e => { App.switchToView('import'); App.handleImport(e.target.files); e.target.value = ''; });
        elements.pkgInfo.addEventListener('click', App.handleFileAction);
        elements.unlockContent.addEventListener('click', App.handleUnlockContent);
    }

    // Initialize this view
    setupImportViewEventListeners();
});