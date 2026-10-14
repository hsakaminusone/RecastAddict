# RecastAddict

RecastAddict patches a Podcast Addict APK (`com.bambuna.podcastaddict`).
Use only an APK that you already have. The tool does the following:

- Unlocks premium gates.
- Removes ad SDKs.
- Redirects telemetry endpoints.
- Writes `RecastAddict-<version>.apk` next to the input file.
- Makes the APK smaller (about 4 MB, ~16 %).

The tool reads the version from the APK. It accepts only the builds in
the table below. It rejects all other files.

## Unlocked premium features

- Subscription: sync, WebSub, locked preferences, customization.
- In-app purchases.
- Donate-app checks for the sync path.
- Installer and certificate checks (necessary: the build is re-signed).
- The "Remove Ad" upsell stays hidden. Ad gates stay closed.

The size reduction comes from deleted ad SDKs, not from compressed
assets.

## Supported versions

| Version | Code | Source |
|---|---|---|
| 2026.12 | 21777 | APKMirror universal APK (all ABIs in one file) |
| 2026.11 | 21774 | APKMirror universal APK (all ABIs in one file) |

### Get the source APK (example: 2026.12 from APKMirror)

1. Open APKMirror. Open Podcast Addict. Open ALL VERSIONS. Select 2026.12.
2. In the variant table, select the universal row (all architectures,
   Android 8.0+, nodpi). Do not select a split or a bundle. If the page
   shows many files, download the single universal APK (~23 MB).
3. Select SEE AVAILABLE DOWNLOADS. Then select DOWNLOAD APK.

## Dependencies

All tools must be on `PATH`. On Windows, use `where` instead of `which`.
The tool checks the dependencies first. If a tool is missing, the tool
shows the install steps for your system.

| Tool | Check command |
|---|---|
| Python 3.9+ | `python3 --version` |
| apktool | `which apktool` |
| `aapt2`, `zipalign`, `apksigner`, `d8` (Android build-tools 35.0.0) | `which aapt2 zipalign apksigner d8` |
| JDK 17+ (`java`, `keytool`) | `java -version` |

### Step 1 — Install Python, apktool, and a JDK

macOS (Homebrew):

```bash
brew install python@3.11 apktool openjdk@17
export PATH="$(brew --prefix openjdk@17)/bin:$PATH"
```

Linux (Debian/Ubuntu):

```bash
sudo apt install python3 openjdk-17-jdk apktool
```

`apt` puts `java` and `keytool` on `PATH`. Without `apt`, get Python
from python.org, get a JDK 17+ (example: Temurin), and follow the
apktool install guide.

Windows:

```powershell
winget install Python.Python.3.11 Microsoft.OpenJDK.17
scoop install apktool
```

Install Scoop first if necessary. Without Scoop, get Python from
python.org, get a JDK 17+ installer, and follow the apktool install
guide.

### Step 2 — Install Android build-tools (one time, all systems)

`aapt2`, `zipalign`, `apksigner`, and `d8` come from one package.
Install the package with `sdkmanager`. `sdkmanager` comes from the SDK
command-line tools. It needs Java on `PATH`. Complete Step 1 first.

1. Get the command-line tools. Use one option:
   - Install Android Studio. It includes an SDK.
   - macOS: `brew install --cask android-commandlinetools`.
   - Manual: download the "commandlinetools" file ("Command line tools
     only") from the official Android Studio download page. Unpack it
     so that `sdkmanager` is at
     `<sdk>/cmdline-tools/latest/bin/sdkmanager`:

     ```bash
     mkdir -p <sdk>/cmdline-tools
     unzip commandlinetools-<mac|linux|win>-*_latest.zip -d <sdk>/cmdline-tools
     mv <sdk>/cmdline-tools/cmdline-tools <sdk>/cmdline-tools/latest
     ```

2. Install build-tools 35.0.0:

   ```bash
   <sdk>/cmdline-tools/latest/bin/sdkmanager "build-tools;35.0.0"
   ```

3. Add the result to `PATH`:
   - macOS/Linux: `export PATH="<sdk>/build-tools/35.0.0:$PATH"`
   - Windows: add `<sdk>\build-tools\35.0.0` to `PATH`

`<sdk>` is your SDK folder: `~/Library/Android/sdk` on macOS,
`~/Android/Sdk` on Linux, `%LOCALAPPDATA%\Android\Sdk` on Windows.
If you use Android Studio, start at step 2 with its SDK folder.

No key setup is necessary. The tool makes a local debug key at first
use.

## Run

From the repo root:

```bash
python3 -m patcher <apk>
```

The tool writes `RecastAddict-<version>.apk` next to the input file
(example: `RecastAddict-2026.12.apk`).

## Checks and tests

```bash
python3 -m ruff check patcher && python3 -m ruff format --check patcher
python3 -m mypy patcher
for t in patcher/tests/test_*.py; do python3 $t; done
```
