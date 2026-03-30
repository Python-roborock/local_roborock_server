# Using the Roborock App

1. Log out of the app on your phone

2. On a machine that is not running the server, run our MITM script:
`uv run mitm_redirect.py --local-api api-roborock.luke-lashley.com`

3. Install the Wireguard app on your phone. Then hit the Plus on the wireguard app, add from QR code and scan the code on
`http://127.0.0.1:8081/#/capture`

4. Open `mitm.it` in your web browser. Follow the instructions there for your device. Note on iphone you must open it in Safari. Make sure you follow all of the device specific steps (including installing the cert, trusting it, etc.)

5. Once Mitm is configured properly, open the Roborock app, log back in, enter your verification code and the server should automatically show you the vacuums you have on your server. Turn off wireguard, disable the mitm certificate, and then click on one of your devices and you should see the map!