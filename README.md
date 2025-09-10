# Nyx Packer: The File Archiver Nobody Asked For

Welcome to Nyx Packer, a stunningly over-engineered solution to a problem that was solved decades ago. Have you ever looked at `.zip`, `.rar`, or `.tar.gz` and thought, "These are just too convenient and widely supported"? Well, you're in luck.

This is a purely client-side web application that allows you to bundle multiple files and folders into a single, bespoke `.nyx` container. It's all processed right in your browser, so your files stay private.

## Why, Though? A Manifesto of Uselessness

This project exists because I was so preoccupied with whether I *could*, I didn't stop to think if I *should*. Nyx Packer "solves" the following "problems":

*   **Universal Compatibility is Boring:** Tired of sending files that anyone can open? The proprietary `.nyx` format ensures your recipient must visit this exact webpage to see what you sent them. It's forced engagement!
*   **An Unhealthy Obsession with JavaScript:** A testament to the fact that with enough JavaScript, you can reinvent any wheel to be slightly less round.

## Features

*   **📦 File & Folder Bundling:** Drag and drop your files and folders to pack them together.
*   **🔐 AES-GCM Encryption:** Secure your package with a password. Because if you're going to use an obscure format, you might as well make it hard to open.
*   **🔪 File Splitting (Sharding):** Chop up large packages into smaller pieces for easier transfer.
*   **📝 Metadata Editor:** Add a package name, author, tags, and description that no one will ever see unless they use this specific tool.
*   **🔑 Master Key:** When you create a package, you get a "Master Key" that lets you edit the metadata later. *Extremely losable. Don't lose it.*
*   **👁️ File Preview:** Preview common file types like images, video, and text directly in the browser.
*   **🔗 Sharable Links:** Generate a single link to import multiple package shards at once, with an optional embedded password.

## How to Use It

The interface is split into multiple tabs for maximum complexity.

### 1. Create Package
1.  **Drag Your Stuff In:** Drop files or folders into the designated area.
2.  **Tweak the Knobs (Optional):**
    *   Set a **Max shard size (MB)** to split the output.
    *   Enter a **password** to encrypt the contents.
    *   Click **Configure Metadata** to fill out forms nobody will read.
3.  **Click "Create":** Your browser will process everything and provide download links for your new `.nyx` file(s) and the Master Key.

### 2. Import Package
1.  **Drag it In:** Drop the `.nyx` file (or all its shards) into the import area.
2.  **Behold the Contents:** The app will parse the header and list the files trapped within.
3.  **Unlock & Download:** If encrypted, enter the password. You can then preview, download individual files, or download everything as a standard `.zip` file.

### 3. Edit Package
1.  **Drop the Package:** Select the `.nyx` file(s) to edit.
2.  **Provide the Master Key:** Enter the key you were given upon creation.
3.  **Fix Your "Mistakes":** Change the metadata or add/change the encryption password.
4.  **Save Changes:** The application will rebuild the entire package.

### 4. Share URL
Sent someone 15 shard links and they got confused? Of course they did. This tab lets you generate a single, clean link to import multiple `.nyx` files at once.

1.  **Paste URLs:** Paste the direct download URLs for your `.nyx` files, one per line.
2.  **Add Password (Optional):** If the package is encrypted, you can add the password here. It will be encrypted and embedded in the link, so the recipient doesn't have to type it.
3.  **Generate Link:** Click the button to create your sharable URL.
4.  **Share:** Copy the resulting URL. When someone opens it, the app will automatically fetch all the specified files and be ready for import.

## The Glorious `.nyx` Format

For the three people who are curious, the format is a masterclass in simplicity.

| Part            | Size (Bytes)   | Description                                                              |
| --------------- | -------------- | ------------------------------------------------------------------------ |
| **Magic Header**| 8              | The bytes `NYXPKG1 ` to identify the file format.                        |
| **Header Length**| 8              | A 64-bit unsigned integer specifying the length of the JSON header.      |
| **JSON Header** | `HeaderLength` | All metadata, file lists, IVs for encryption, and split info.            |
| **Payload**     | The rest...    | The actual file data, concatenated together.                             |

---

**A Final Word of Warning:** **Do not use this for anything important.** This is a portfolio piece and a fun exercise in learning the File System Access API, Web Crypto API, and handling large data in the browser.