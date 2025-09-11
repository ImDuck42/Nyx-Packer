document.addEventListener('DOMContentLoaded', () => {
    'use strict';
    
    //=================================================================================
    //  EDITOR MODULE
    //=================================================================================
    const Editor = {
        // Unlocks the editor form after master key verification
        unlockForm: (header) => {
            State.mut('isEditorUnlocked', true);
            elements.editKeyVerification.classList.add(CONFIG.CLASSES.hidden);
            elements.editForm.dataset.locked = "false";
            Editor.displayMetadataForm(header);
        },

        // Populates the metadata form with data from a package header
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

        // Clears the editor view and resets its state
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

        // Retrieves and validates metadata from the editor form
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

        // Rebuilds the package with only metadata changes
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

        // Rebuilds the package, applying changes to encryption settings
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
    window.Editor = Editor;

    // Extend the App module with edit-specific handlers
    Object.assign(App, {
        // Returns from the metadata configuration mode to the main 'Create' view
        returnToCreateView: (switchView = true) => {
            State.mut('isConfiguring', false);
            elements.editZone.parentElement.classList.remove(CONFIG.CLASSES.hidden);
            elements.editDownload.classList.remove(CONFIG.CLASSES.hidden);
            elements.editForm.classList.add(CONFIG.CLASSES.hidden);
            elements.saveChanges.innerHTML = `<span aria-hidden="true">💾</span> Save Changes`;
            if (switchView) App.switchToView('create');
        },

        // Handles loading a package into the 'Edit' view
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

        // Handles the 'Verify' button click for the master key in the 'Edit' view
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

        // Handles the 'Save Changes' button click in the 'Edit' view
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
        
        // Sets up event listeners for the 'Edit' view
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
    });
});