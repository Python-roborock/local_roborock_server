# Using the Roborock App

Use this after [Installation](installation.md) and [Onboarding](onboarding.md) if you want the official Roborock app to talk to your local stack.

## iPhone

1. Log out of the app on your phone.

2. On a machine that is not running the server, run the MITM script:

   ```bash
   uv run mitm_redirect.py --local-api api-roborock.example.com
   ```

3. Install the WireGuard app on your phone. Then tap the plus button in WireGuard, choose to add from QR code, and scan the code at `http://127.0.0.1:8081/#/capture`.

4. Open `mitm.it` in your web browser (iPhone). Follow the instructions there for your device. In Safari, complete all device-specific steps, including installing and trusting the certificate.

5. Once the MITM setup is working, open the Roborock app, log back in, enter your verification code, and the server should automatically show the vacuums already known to your local stack. Turn off WireGuard, disable the MITM certificate, and then open one of your devices to confirm the map loads.

## Android

> **Note:** It is recommended to disable auto update in the Roborock App.

> **Note:** This workaround has only been tested and confirmed working on Roborock app version **4.60.06**. Newer versions may ship a different `librrcodec.so` with different offsets, in which case the patch script will need to be updated.

Android 7+ (API level 24+) only trusts system certificates, so the app will reject the MITM certificate by default. On top of that, the Roborock app includes a native library (`librrcodec.so`) that checks the APK's signing certificate on startup and kills the process if it doesn't match, meaning a simple `apk-mitm` patch isn't enough.

To work around both issues, you need to patch `librrcodec.so` to remove the integrity check, then repackage the APK.

### Prerequisites

Make sure you have the following installed:

- [apk-mitm](https://github.com/nicbarker/apk-mitm) (`npm install -g apk-mitm`)
- [apktool](https://apktool.org/)
- [apksigner](https://developer.android.com/tools/apksigner) (part of Android SDK build-tools)
- [keytool](https://docs.oracle.com/en/java/javase/17/docs/specs/man/keytool.html) (part of JDK)
- [Python 3](https://www.python.org/downloads/)

### Patching the APK

1. Download the Roborock APK (e.g. from [APKMirror](https://www.apkmirror.com/apk/roborock/roborock/)) and place it in your working directory.

2. Run `apk-mitm` to patch the APK for certificate trust:

   ```bash
      apk-mitm roborock.apk
   ```

3. Decompile the patched APK:

   ```bash
      apktool d roborock-patched.apk -o roborock_work
   ```

4. Patch `librrcodec.so` to remove the signature integrity check.

   First, save a copy of the original `librrcodec.so` as `librrcodec.so.bak`.

   ```bash
      cp roborock_work/lib/arm64-v8a/librrcodec.so roborock_work/lib/arm64-v8a/librrcodec.so.bak
   ```

   Now run the patcher from the repository root using the script in `patcher/`. You can pass the path to `librrcodec.so` explicitly (as shown below), or run it with no arguments from inside the unpacked APK and it will find the file itself.

   > Use `python` or `python3` depending on your system (Python 3.8+ is required).

      ```bash
         python patcher/patch_librrcodec.py roborock_work/lib/arm64-v8a/librrcodec.so
      ```

5. Rebuild the APK:

   ```bash
      apktool b roborock_work -o roborock_final.apk
   ```

6. Sign the APK. You have two options:

   **Option A** — Create a new signing key and sign:

   ```bash
      keytool -genkey -v -keystore my-key.keystore -alias mykey -keyalg RSA -keysize 2048 -validity 10000
      apksigner sign --ks my-key.keystore roborock_final.apk
   ```

   **Option B** — Use an existing JKS keystore:

   ```bash
      apksigner sign --ks my-key.jks --v1-signing-enabled true --v2-signing-enabled true roborock_final.apk
   ```
7. Uninstall the original Roborock app from your phone (required because the signing key is different), then install the patched APK:

   ```bash
      adb uninstall com.roborock.smart
      adb install roborock_final.apk
   ```

8. On a machine that is not running the server, run the MITM script:

   ```bash
      uv run mitm_redirect.py --local-api api-roborock.example.com
   ```

9. Install the WireGuard app on your phone. Then tap the plus button in WireGuard, choose to add from QR code, and scan the code at `http://127.0.0.1:8081/#/capture`.

10. Open `mitm.it` in your web browser (Android). Follow the instructions there for your device. In Chrome, complete all device-specific steps, including installing and trusting the certificate.

11. Once the MITM setup is working, open the Roborock app, log back in, enter your verification code, and the server should automatically show the vacuums already known to your local stack. Then close the Roborock app, turn off WireGuard, disable or delete the MITM certificate, reopen the Roborock app, and select your device or devices to confirm the map loads.


### What the patch does

During `JNI_OnLoad`, `librrcodec.so` calls a verification function that retrieves the APK's signing certificate via `PackageManager.getPackageInfo()`, hashes it with `MessageDigest`, and compares it against a hardcoded value. If the hash doesn't match, it calls `Process.killProcess()`. The patch replaces the two `BL` (branch-link) instructions that call this function with `NOP`, so the check never runs. In the disassembly, these call sites are at VA `0x4bdcc` and `0x4c428`; in `patcher/patch_librrcodec.py`, the corresponding file offsets are `0x4adcc` and `0x4b428`. The crypto functions the app actually needs are unaffected.

> **Note:** This patch has only been tested and confirmed working on Roborock app version **4.60.06**, against the `librrcodec.so` with build ID `becc35bc1a75903df1eae3f90b380ca5403d06cb`. If Roborock releases a new app version, the virtual addresses and file offsets may change and the patch script will need to be updated.

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Home Assistant](home_assistant.md)
