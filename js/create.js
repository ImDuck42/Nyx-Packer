document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    // Extend the UI module with create-specific functions
    Object.assign(UI, {
        // Renders the list of files staged for creation
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

        // Updates the state of the 'Create' view based on current application state
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
        
        // Displays the master key area
        showMasterKey: (masterKey) => {
            elements.masterKeyOutput.value = masterKey;
            elements.masterKeyArea.classList.remove(CONFIG.CLASSES.hidden);
        },

        // Hides the master key area
        hideMasterKey: () => elements.masterKeyArea.classList.add(CONFIG.CLASSES.hidden),

        // Clears the download links area
        clearDownloadArea: () => elements.download.innerHTML = '',
    });

    // Extend the App module with create-specific handlers
    Object.assign(App, {
        // Handles the 'Create Package' button click
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
        
        // Handles the 'Configure Metadata' button click
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
    });

    // Encapsulated setup function for this view
    function setupCreateViewEventListeners() {
        elements.uploadZone.addEventListener('click', () => elements.fileInput.click());
        elements.fileInput.addEventListener('change', e => { State.addFiles([...e.target.files].map(f => ({ file: f, fullPath: f.name }))); e.target.value = ''; });
        elements.create.addEventListener('click', App.handleCreate);
        elements.clear.addEventListener('click', () => { if (State.getState().files.length > 0) { State.resetCreateView(); UI.showToast('All files cleared', 'success'); } });
        elements.copyKey.addEventListener('click', () => { navigator.clipboard.writeText(elements.masterKeyOutput.value); UI.showToast('Master key copied!', 'success'); });
        elements.splitSize.addEventListener('input', UI.updateCreateViewState);
        elements.configureMetadata.addEventListener('click', App.handleConfigureMetadata);
        
        // Use event delegation for file list actions
        elements.fileList.addEventListener('click', async (e) => {
            const button = e.target.closest('button[data-action]');
            if (!button) return;
            const { action, index } = button.dataset;
            const fileIndex = parseInt(index, 10);

            if (action === 'remove') {
                const { files } = State.getState();
                const [removed] = files.splice(fileIndex, 1);
                document.querySelector('.inline-preview-container')?.remove();
                State.setFiles(files);
                UI.showToast(`Removed "${removed.fullPath}"`, 'success');
            } else if (action === 'preview') {
                const fileObject = State.getState().files[fileIndex];
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
    }

    // Initialize this view
    setupCreateViewEventListeners();
    UI.updateCreateViewState();
});