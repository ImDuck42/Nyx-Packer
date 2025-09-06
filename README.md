# Nyx Packer: The File Archiver Nobody Asked For



Welcome to Nyx Packer, a stunningly over-engineered solution to a problem that was solved decades ago. Have you ever looked at `.zip`, `.rar`, `.7z`, or `.tar.gz` and thought, "These are just too convenient, too widely supported, and far too efficient"? Well, you're in luck, because I've created something demonstrably worse in every metric that matters.

This is a purely client-side web application that allows you to bundle multiple files and folders into a single, bespoke `.nyx` container. It's all processed right in your browser, so you can keep your precious files away from my (or any) server, which is probably the only genuinely good feature here.

## Why, Though? A Manifesto of Uselessness

I'll be honest with you. This project exists because I was so preoccupied with whether I *could*, I didn't stop to think if I *should*. Nyx Packer is the digital equivalent of building a custom car that only runs on artisanal, gluten-free gasoline and can only be repaired with tools you have to forge yourself.

It "solves" the following "problems":
*   **Universal Compatibility is Boring:** Tired of sending files that anyone can open? The proprietary `.nyx` format ensures your recipient will have to visit this exact webpage just to see what you sent them. It's forced engagement!
*   **You Have Too Much Free Time:** Why simply zip and send when you can embark on a multi-step journey of creating, configuring metadata, generating a master key, and then explaining the whole convoluted process to someone else?
*   **Fear of the Command Line:** This provides a GUI for tasks that are arguably faster and more powerful in a terminal, but hey, buttons are shiny.
*   **An Unhealthy Obsession with JavaScript:** It's a testament to the fact that with enough JavaScript, you can reinvent any wheel to be slightly less round.

## Features (That You Could Get Elsewhere, But Here They Are Anyway)

Nyx Packer is bursting with features that have been standard in other archivers since the dawn of computing. But here, they're built with modern web technologies, which makes them better, somehow.

*   **📦 File & Folder Bundling:** Drag and drop your files. Or your folders. It'll dutifully pack them all together. Groundbreaking, I know.
*   **🔐 "Military-Grade" Encryption:** Slap some AES-GCM encryption on your package. Because if you're going to use an obscure format, you might as well make it hard to open even if someone *does* figure it out.
*   **🔪 File Splitting (Sharding):** Got a file too big for Discord, email, or your favorite carrier pigeon? Nyx Packer can chop it up into smaller, more manageable pieces based on a size you specify.
*   **📝 Metadata Editor:** Pretend you're a professional archivist by adding a package name, author, tags, and a description. No one will ever see it unless they use this specific tool, but *you'll* know it's there. That's what counts.
*   **🔑 Unlosable\* Master Key:** When you create a package, you get a "Master Key." This all-important key lets you... edit the metadata later. The stakes have never been lower.
    *   *\*Extremely losable. Don't lose it. Or do. It probably doesn't matter. (You can also just edit the metadata in the file directly sooo...)*
*   **👁️ File Preview:** For common file types like images, video, audio, and text, you can get an inline preview without downloading the whole package. A genuinely useful feature.

## How to "Use" This Thing

The interface is split into three tabs, because anything worth doing is worth overcomplicating.

### 1. Create Package

This is where the magic (and your poor judgment) begins.

1.  **Drag Your Stuff In:** Drop files or entire folders into the designated area.
2.  **Tweak the Knobs (Optional):**
    *   Set a **Max shard size (MB)** if you want to split the output into multiple files. Leave it blank for one big file.
    *   Enter a **password** to encrypt the contents.
    *   Click **Configure Metadata** to waste time filling out forms nobody will read.
3.  **Smash the "Create" Button:** Your browser will groan under the weight of processing everything, and eventually, you'll be presented with download links for your shiny new `.nyx` file(s) and the all-powerful Master Key. Copy that key. Or don't. Live dangerously.

### 2. Import Package

You've received a `.nyx` file. My condolences.

1.  **Drag it In:** Drop the `.nyx` file (or all of its shards, if it was split) into the import area.
2.  **Behold the Contents:** The application will parse the header and display the package information and a list of the files trapped within.
3.  **Unlock & Download:** If the package is encrypted, you'll be prompted for the password. Once unlocked, you can preview, download individual files, or download the whole lot as a standard, infinitely more useful `.zip` file.

### 3. Edit Package

You found a typo in the package description you wrote at 3 AM. A crisis.

1.  **Drop the Package:** Select the `.nyx` file(s) you want to edit.
2.  **Provide the Sacrificial Key:** Enter the Master Key you were given upon creation. If you lost it, congratulations, that metadata is now a permanent monument to your past self. All that can save you now is a text editor won't crashin under the wheight of gibberish in the files content.
3.  **Fix Your "Mistakes":** Change the name, author, description, or even add/change the encryption password and let the file travel through time.
4.  **Save Changes:** The application will rebuild the entire package from scratch with your new metadata. It's wildly inefficient, but it gets the job done.

## The Glorious `.nyx` Format

For the three people who are curious, the `.nyx` format is a masterclass in simplicity built on the shoulders of giants.

| Part                | Size (Bytes)  | Description                                                                                             |
| ------------------- | ------------- | ------------------------------------------------------------------------------------------------------- |
| **Magic Header**    | 8             | The bytes `NYXPKG1 ` to prove it's one of ours. It's like a secret handshake for files.                   |
| **Header Length**   | 8             | A 64-bit unsigned integer telling you how big the next JSON part is.                                    |
| **JSON Header**     | `HeaderLength` | All your metadata, file lists, IVs for encryption, and split info, in a trendy, human-readable format. |
| **Payload**         | The rest...   | The actual file data, concatenated together. You know, the only part that actually matters.             |

## A Final Word of Warning

**Do not, under any circumstances, use this for anything important.** This is a toy. A portfolio piece. A cry for help. It was built as a fun exercise in learning the File System Access API, Web Crypto API, and handling large amounts of data in the browser.

All the heavy lifting is done by the brilliant `JSZip` library and the native `Web Crypto API` in your browser. My contribution was gluing them together in the most convoluted way I could imagine.