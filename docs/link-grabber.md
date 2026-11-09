# Link grabber and archives

[← Back to docs index](README.md)

**Link grabber** gathers many links at once, sorts them into packages, and lets you tick the ones to download. MDM can then extract the archives it downloaded (zip, 7z, rar and more), by itself or when you ask.

![Link grabber](images/grabber.webp)

## Where links come from

- **The browser.** Right-click a page for **Download all links with Mister Download Manager**, or select part of it for **Download selected links with Mister Download Manager**. The page's referrer and cookies go with each link.
- **Tasks → Import → From text file** and **From IDM export file**. An `.ef2` file brings each download's referrer and cookies.
- Several links, or a `.txt` or `.ef2` list, dropped on the download list.
- **Pasting.** Choose **Tasks → Link grabber...** and press **Ctrl+V**: every web address in the copied text is added.
- **DLC containers** (`.dlc` files, from JDownloader and many link sites): open one with MDM, drop it on the download list, or pick it in **Tasks → Import → From text file**. See [DLC containers](#dlc-containers).
- **Click'n'Load** buttons on link sites, once you turn it on. See [Click'n'Load](#clickn-load).

Links that come while the window is open join the ones already there. A link that is already in the window isn't added twice. A link that is already in your download list goes under **Already in the list**, unticked.

## Packages

Each package is a row you can open and close (click its arrow, double-click it, or press **Right** and **Left**). Ticking a package ticks all its links; its box is half-filled when only some are ticked.

- **The volumes of one archive** (`movie.part1.rar`, `movie.part2.rar`…, or `backup.7z.001`, `backup.7z.002`…) form one package named after the archive, as long as they come from the same site.
- **The other links of one page** form a package named after the page.
- **Everything else** goes into **Various files**.
- **Links a site packed** (a DLC container, Click'n'Load) keep the site's packages and names, with their archive password when the site gave one.

## DLC containers

A DLC file holds a site's links, encrypted. Its key is kept by JDownloader's makers on their key service, so MDM asks that service for it, over HTTPS: the service gets the container's short key part, never its links. Then the packages appear in Link grabber, to tick as any links.

To be plain about it: DLC has no public specification, and JDownloader's makers publish no key for other programs. MDM learned the file's layout by looking at containers and the service's answers by asking it, and it uses the one program key that is public: the one pyLoad, a free download manager, publishes in its source. So MDM asks the service under pyLoad's name (its own name stays in the request's User-Agent). If the service stops answering that name, MDM says it couldn't get the key, and the container can't be opened; the site's Click'n'Load button or plain links still work.

Older containers (`.ccf`, `.rsdf`) aren't read: their keys are not public either, and sites have long stopped making them.

## Click'n'Load

Many link sites have a **Click'n'Load** button that sends their links straight to a download manager on your computer, as JDownloader's documentation for web sites describes. Turn it on in **Options → Archives and Link grabber → Accept Click'n'Load from web pages** (off by default). MDM then listens on port 9666 of this computer only, and the links a page sends open in Link grabber, with the page's package name and archive password.

- Any page could send links, so nothing is ever downloaded until you tick it in Link grabber.
- Only one program can listen on port 9666. If JDownloader is running, MDM says so: close it, then turn the option off and on again.
- A button that sends a DLC container instead of links works too: MDM reads it as a `.dlc` file.
- Some sites hide the key in a script MDM doesn't run (only the plain form the documentation shows is read): then their button reports a failure, and the site's DLC file or plain links are the way.

## Looking links up

As links arrive, MDM asks each server about its file, as IDM's **Download all links** does. A few links are checked at a time, and only a few from any one site. Each link then shows its real name and size, and a status:

- **Online**: the server has the file.
- **Offline (404)**: it doesn't. The link is unticked.
- **Needs a login**: the server wants a user name and password, or the page's cookies.
- **Busy, try later**: the server asked to wait.

Turn the look-ups off in **Options → Archives → Look links up when they arrive**. Some file hosts count a look-up as a download.

**Hide web pages** (on by default) leaves out links to pages (`.html`, `.php` and the like): they are neither shown nor downloaded.

## The package box

The box under the list edits the package you selected:

- **Name**: the package's name, kept with its downloads.
- **Save to**: the folder its files go to. When a package holds several kinds of files, the box says **Each file's category folder**: each file goes to its category's folder (**Options → Save to**), as Import always did.
- **Password**: the archives' password, if they have one. It is kept in memory only, never written to disk.
- **Extract when done**: ticked by itself when the package holds an archive.
- **Delete archives after extracting**: once extracted, the archives go to the Recycle Bin (the Trash on macOS and Linux).

## Adding the links

- **Start** adds the ticked links to the **Main download queue** and starts the queue. It downloads as many files at once as the queue allows.
- **Add to queue** adds them to the **Main download queue** without starting them, as IDM's import does.
- **Cancel** closes the window and adds nothing.

## Extracting archives

MDM itself extracts zip archives (AES-encrypted and Deflate64 ones too), tar, tar.gz and tar.xz archives, and single `.gz` and `.xz` files.

**7z and RAR archives need 7-Zip**, a free program ([7-zip.org](https://www.7-zip.org/)). MDM runs it when it is installed, for split and encrypted archives too. RAR's own extraction code can't be part of a free program like MDM, and 7-Zip extracts 7z best.

**Options → Archives** says whether 7-Zip was found. Without it, a 7z or RAR archive isn't extracted, and the **7-Zip needed** window says so, with a **Get 7-Zip** button.

An archive is extracted:

- when its package says **Extract when done**,
- when **Options → Archives → Extract archives when their download completes** is on (off by default), for any other download,
- when you right-click a finished archive and choose **Extract**.

A split archive is extracted once, when its last volume is downloaded. The files go next to the archive:

- into a folder named after the archive when it holds several things at its top (or always, or never: **Options → Archives**),
- a file that is already there is kept, and the new one is numbered: `report (1).txt`.

Extracted files are marked as coming from the internet, as the archive is, so Windows still warns before running a program from it.

MDM extracts safely. A name that would lead outside the folder is left out, and so is a link to somewhere else on the disk. An archive that would write far more than its size, or more than the disk has room for, stops before it fills it. When something goes wrong, nothing but the archive is left behind.

The download's log (hover over it in the list) says what happened: **Extracted 12 files to …**, or why not, for example **Couldn't extract movie.7z.001: volume 3 of it is missing**. An encrypted archive without its password opens the **Archive password** window. Type the password and click **Extract**, or **Cancel** to leave the archive as it is.

## Next steps

- [Adding downloads →](adding-downloads.md)
- [Options → Archives →](options.md#archives)
- [Browser integration →](browser-integration.md)
