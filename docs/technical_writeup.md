# Freeing Roborock vacuums from the cloud.
Roborock vacuums communicate over three protocols. 

1) REST - a number of things happen over REST primarily during onboarding.

2) MQTT - The vacuum communicates with the Roborock cloud using MQTT.

3) TCP - The vacuum communicates locally with your phone over a TCP transport.

## Reverse engineering Roborock's messaging

### Mitm/ wireshark reverse engineering

When we first started to reverse engineer things for Roborock, we used [mitmproxy](https://www.mitmproxy.org/) which could get all of the REST messages along with the encrypted MQTT messages. We also would use [wireshark](https://www.wireshark.org/) with a rvictl interface setup that allowed our iphones network to go through the mac. This allowed us to see and understand how the local connection worked as well as to see all of the messages on the local connection (partially) unencrypted. This worked for a while, but it started to fall short when you ran into cases where different vacuums support different arguments and different methods.

### App reverse engineering

Roborocks app contains logic about onboarding, rest requests, and base level generic logic. Then, when you open up a vacuum for the first time, it installs a react native bundle and that holds all of the vacuum specific logic (commands, attributes, status codes, etc.)

I have used [jadx](https://github.com/skylot/jadx) to reverse engineer logic in the Roborock APK. Then, we have a function in python-roborock that allows you to download the react native bundle for any vacuum. Most vacuums share the same react native bundle with some specific logic around conditional feature support. The react native bundles are stored as hermes bytecode which I decompile with [hermes-dec](https://github.com/P1sec/hermes-dec) and then I use a custom script that uses [AST](https://en.wikipedia.org/wiki/Abstract_syntax_tree) to break up the decompiled code into separated files and make it more readable javascript. There are around 3000 files that make up the bundle.

## Vacuum Onboarding

I quickly realized my best bet of ever getting the vacuum to work 100% locally would be by taking control of the onboarding process. To onboard the vacuum, your phone connects to a SSID on the vacuum and then communicates directly with the vacuum over UDP. At the time I figured this logic out, I did not have any vacuum firmware or root access into the vacuum and MITM would not work as it was communicating over a private network, so I determined the logic using my computer to be the phone/vacuum. I made my computer broadcast a SSID that the Roborock app would accept. Then I opened a UDP server on my computer. My phone would send the first message to my computer, I would store the response and reverse engineer it, then my computer would connect to the real SSID on the vacuum and send the message there and record its response. I did this back and forth until my computer could go through the entire onboarding flow as either party (either the app or the vacuum).

Here is how the flow works:
1) The app generates a private/public key pair and sends a hello to the vacuum

Phone -> Vacuum:
`{"id":1,"method":"hello","params":{"app_ver":1,"key":"public key here"}}`

2) The vacuum Responds with a message that is encoded with the public key that was provided in message 1, since we created the private key, we are able to decode it:
`{"id":1,"params":{"key":"A1B2C3D4E5F6G7H8"}}`

3) We send the wifi and other configuration to the vacuum using AES-encryption with the session key that was returned in step 2.
`{"u":"1234567890","ssid":"My Wifi","token":{"r":"us","tz":"America/New_York","s":"S_TOKEN_0123456789abcdef","cst":"EST5EDT,M3.2.0,M11.1.0","t":"T_TOKEN_fedcba9876543210"},"passwd":"Password123","country_domain":"us"}`

4) The vacuum takes the region from step 3 and injects it into a url to know where to hit.
i.e. 'us' is injected into `api-%s.roborock.com` and it becomes `api-us.roborock.com`

The vacuum then requests the region from the server
`GET /region?did=1103811971559&pid=roborock.vacuum.a27&ts=1712345678&nonce=abc123&signature=MEUCIQDmExampleSignaturePart1%2BAbCdEfGhIjKlMnOpQrStUvWxYz%3D%3DAiEAExampleSignaturePart2%2F1234567890abcdef%2B%2F%3D`

It passes the device id of the vacuum, the product id, a nonce, and a signature (this will be important later)

5) The server responds by sending back all of the region information encoded by a public key that exists on the Roborock server.
```json
{
  "success": true,
  "code": 200,
  "msg": "success",
  "data": {
    "apiUrl": "https://api-us.roborock.com",
    "mqttUrl": "ssl://mqtt-roborock.com:8883",
  },
  "result": {
    "apiUrl": "https://api-us.roborock.com",
    "mqttUrl": "ssl://mqtt-roborock.com:8883",
  }
}
```

## Taking control of onboarding

[rovo89](https://github.com/rovo89) was the one who pointed out to me that the vacuum is injecting the url in from the response of the payload. He had previously looked through the firmware code and that caught his eye. Since I could do the full onboarding cycle I decided to try injecting a custom url. Instead of passing in 'us', I would pass in 'myserver.domain.com/'. This means the url the vacuum hits would actually become 'api-myserver.domain.com/.roborock.com/region'.

The vacuum accepted this as it had no max length constraint or any other sanitization. I got the vacuum to connect to a server I started up, but it would not accept my response to the region endpoint as I did not have a public key that was stored on the Roborock servers. I used [dustbuilder](https://dustbuilder.dontvacuum.me/_a15.html) to install custom firmware on my S7. I used this to get the private key off of the vacuum and I was able to encode the response properly to the point that the vacuum would connect to my web server and even my mqtt server (temporarily). I had to host the server with a certificate that would pass TLS validation. However, I stopped here as my thought was the solution was not realistic. Since the public key is inaccessible on Roborock's servers, the only way to encode the messages properly was with the private key. To get the private key, you had to disassemble the vacuum, flash it, install custom firmware on it, etc. And it only worked for a handful of vacuums. If you go through all of that effort, there is no reason you shouldn't just install [Valetudo](https://valetudo.cloud/). So, I had given up hope in early 2025.

## Agentic Reverse Engineering

Fast forward to early 2026. AI tools were now significantly better than they were a year ago, I knew more about reverse engineering, more about Roborock's apps, protocols, etc. I decided I would give it one more try this time with agents. Context is key for good agentic work, so I gave it the following:

1) Access to SSH into my rooted Roborock S7

2) Access to the Roborock S7 firmware file

3) python-roborock

4) The Roborock app APK

5) The decompiled react native bundles.

6) My previous code that allows for controlling the onboarding process.

I did not want to bias the agent with my approach that I figured was a dead end, I wanted to let the agent explore naturally and see what it finds. I started by using Opus 4.6, but Claude code's $20 subscription was constantly running out of usage, so I switched to Codex 5.3 max on their $20 plan, which would run for probably 4-5x as long without running out of usage.

### Step Zero: A way for the agent to validate its work

The best agentic output will come when the agent can validate its findings and hypotheses. The roborock firmware I had previously downloaded from dustbuilder made it clear that the vacuum was essentially just running Ubuntu. So if I could figure out how to get the vacuum running locally, it would mean that the agent could continuously try real approaches with a simulated vacuum, rather than me having to interact with the vacuum in the real world for every single attempt. I got the firmware emulated in a QEMU-backed ARM chroot, which gave the agent a lot of power to validate its findings.

### Step One: Find an exploit

While it wasn't as simple as just telling the agent: 'Find an exploit for local control - make no mistakes.', I did decide to let the agent take the lead here, I didn't want to bias the agent with my failed attempt, I wanted it to see if it could find an exploit that it thought was promising. After a lot of thinking and exploring by the agent, documenting its findings, and me shutting down a few of its ideas (i.e. just changing the DNS record for the roborock servers to point to our own which would fail as it would not be a trusted cert), the agent determined the best possible path forward was what I tried a year ago. I once again figured it was DOA, but I decided to continue on and see if the agent saw something I didn't.

### Step Two: The public key

We need either the public key (stored on Roborock's servers) or the private key (stored on the vacuum) in order to finish the onboarding. Getting the private key requires rooting the vacuum - that's the dead end I hit before. The public key lives on Roborock's servers and isn't exposed through any API. So I was unsure how to get it.

Remember step 4 of the onboarding flow - the vacuum hits the `/region` endpoint and passes a `signature` parameter. That signature is an RSA PKCS1v1.5 SHA-256 signature over the query string, signed with the vacuum's private key. We can't access the private key, but we don't need to. We just need the public key. With enough signature samples, we can actually determine the public key.

Here's the math. RSA PKCS#1 v1.5 signing computes `sig = pad(SHA256(msg))^d mod n`, where `pad()` is the deterministic EMSA-PKCS1-v1.5 encoding (a fixed ASN.1 prefix + the hash, right-padded into a full block). Verification checks `sig^e mod n == pad(SHA256(msg))`. We know `e` (65537 is the standard RSA public exponent used by most implmenetations), we can compute `pad(SHA256(msg))` ourselves (it's deterministic given the query string), and we know the signature as it is included in the REST request. What we don't know is `n` — the RSA modulus, which is the public key.

If we rearrange the verification equation: `sig^e - pad(SHA256(msg)) = k * n` for some integer `k`. That means the difference is a multiple of `n`. If we collect two different signed requests from the vacuum (different query strings, different signatures), we get two different multiples of `n`. The GCD of those two values gives us `n` - or `n` times some small cofactor that we can divide out. The padding being deterministic is what makes this work — if it included any randomness, we couldn't compute the padded value and the recovery would be impossible.

So the approach is:
1) During onboarding, we inject our server URL so the vacuum connects to us.

2) The vacuum sends signed requests to our server (the `/region` endpoint and others).

3) We capture at least two requests with different query strings and their signatures.

4) We compute `sig^e - padded_message` for each pair, take the GCD, strip any small prime cofactors, and verify the candidate modulus against all captured signatures.

5) Once we have the modulus, we reconstruct the full RSA public key (modulus + exponent 65537).

6) With the public key, we can now encrypt the bootstrap response exactly like Roborock's servers do

I prompted the agent towards trying to determine the public key, I didn't think something like this was an option, as in my head any kind of key recovery is incredibly computational complex. However, the agent explored the signature verification code in the firmware, realized the math worked out and pointed me in the right direction. We used [gmpy2](https://github.com/aleaxit/gmpy2) for the arithmetic since we're dealing with 2048-bit numbers and using Python builtins would be very slow.

### Step Three: Connection

The vacuum requires TLS for both the MQTT connection and the REST connections. It also verifies the certificate is valid for the domain listed. Since we are able to inject our own domain, this part is pretty trivial. You just need a domain name that you own and this can be done very easily.

### Step Four: Messaging

This was actually probably the easiest part! Like I said, Roborock supports both a local TCP transport and MQTT. The local TCP transport just works as the connection between the vacuum and the app are unchanged. The MQTT connection is pretty simple as well. Each device has four types of topics:

`rr/d/i/{did}/{mqtt_user}` Vac -> Server

`rr/d/o/{did}/{mqtt_user}` Server -> Vac

`rr/m/i/{hashed user information}/{userid}/{duid}` User -> Server

`rr/m/o/{hashed user information}/{userid}/{duid}` Server -> User

did and duid are two different identifiers for the vacuum. 

We simply have to take any messages that come onto the rr/d/i topics and publish them to the appropriate rr/m/o topics. Then any messages that come onto rr/m/i and publish them to the appropriate rr/d/o topics. And then MQTT messaging is working!

### Step Five: The App

I had actually previously attempted this a year ago when I was first trying to find this out. This is another rather simple part of the system comparatively. To get the app working natively, I used MITM to capture incoming REST calls and rewrite the responses. You sign in to the app and the app returns back the 'user data' which contains the URLs for all of Roborock's servers. We replace the urls with our servers url and the app will then do all future connections/ api calls to our server instead of the cloud. We can turn off MITM.

## The verdict

This exploit is the best kind of exploit, it is one with no risk. The only way someone can take advantage of this is if they have physical access to the vacuum and the users network and it can be undone in seconds. I do however wish this was not needed. Roborock could have EASILY made their vacuums fully support local control. The fact that all map requests MUST go through Roborock's cloud server when the map is located on the device is definitely odd to me. By allowing the map requests to go through local connections and not forcing the vacuum to do a network dump whenever it loses connection, Roborock could have devices that could work 100% offline. 