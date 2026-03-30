# Onboarding

You can follow this guide whenever you setup a vacuum. If it is a new vacuum, I'd recommend first setting it up on the Roborock app with the official servers and then go through the onboarding here. That way you can be sure your app has installed all of the artifacts it needs for that vacuum and you can check that it is up to date on it's firmware.

1. You need to go through this cycle 2-4 times. I recommend having the admin dashboard up (https://api-roborock.example.com)

2. On a machine that is NOT running the server, you need to run the onboarding script found in this repo. 

You need to determine the following parameters:

server: This is your server WITHOUT the api- and it should end with a '/' i.e. roborock.example.com/ The onboarding script should help you out if you make a mistake.

ssid: This is the name of the network you want the vacuum to connect to, if there is a space make sure to surround it in quotes.

password: This is your networks password

cst: This is your POSIX timezone. Here are some common ones:

Eastern Time (US): EST5EDT,M3.2.0,M11.1.0

Central Time (US): CST6CDT,M3.2.0,M11.1.0

Mountain Time (US - with DST): MST7MDT,M3.2.0,M11.1.0

Mountain Time (Arizona - no DST): MST7

Pacific Time (US): PST8PDT,M3.2.0,M11.1.0

London (UK): GMT0BST,M3.5.0,M10.5.0

Central Europe (Paris/Berlin): CET-1CEST,M3.5.0,M10.5.0

India (No DST): IST-5:30

Japan (No DST): JST-9

country-domain: Two letter key for your country domain, I'm not sure how this is utilized by the vacuum but 'us' is the valid key for the USA.

timezone: IANA Time Zone Database identifier i.e. 'America/New_York"


Example command:
`uv run onboarding.py --server roborock.example.com/ --ssid "My Wifi" --password "Password123" --cst EST5EDT,M3.2.0,M11.1.0 --timezone "America/New_York"`

3. The script will walk you through the onboarding process. But you need to Reset the vacuums wifi (You can do this by holding the two buttons on your dock if your vacuum has just two buttons) or by holding the left and right button if your vacuum has three buttons. Hold for 3-5 seconds until you hear "Resetting Wifi". You can find specific instructions for your vacuum by Googling: "How to reset wifi Roborock ..."

4. Connect to your vacuum's wifi SSID on a computer that is NOT running the server. Give it a second and then continue on the script.

5. You will hear the vacuum say 'Connecting to Wifi - Stand by"

6. Check the UI and wait for the "Num Query samples" count to go up by 1. Once it goes up, you can do another cycle on the onboarding script. Some vacuums seem more resistant than others. So the amount of times you have to do it may vary.

![Sample](sample_example.png)

7. Repeat this until you hear the vacuum say "Wifi Connected" It will take 2-3 times. Once you do it twice, wait a few minutes between tries to ensure that the vacuum has enough time to finish the onboarding cycle.

Congrats! The vacuum is now free of the cloud!