# Using the Roborock App

ONLY WORKS ON IOS FOR NOW! Android does certificate pinning that makes this harder to do. See info [here](https://github.com/Python-roborock/local_roborock_server/issues/5#issuecomment-4223935907)

Use this after [Installation](installation.md) and [Onboarding](onboarding.md) if you want the official Roborock app to talk to your local stack.

1. Log out of the app on your phone.

2. On a machine that is not running the server, run the MITM script:

   ```bash
   uv run mitm_redirect.py --local-api api-roborock.example.com
   ```

3. Install the WireGuard app on your phone. Then tap the plus button in WireGuard, choose to add from QR code, and scan the code at `http://127.0.0.1:8081/#/capture`.

4. Open `mitm.it` in your web browser. Follow the instructions there for your device. On iPhone, open it in Safari and complete all device-specific steps, including installing and trusting the certificate.

5. Once the MITM setup is working, open the Roborock app, log back in, enter your verification code, and the server should automatically show the vacuums already known to your local stack. Turn off WireGuard, disable the MITM certificate, and then open one of your devices to confirm the map loads.

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Home Assistant](home_assistant.md)
