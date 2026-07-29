# Shared Setup

Use this page first for the setup details that apply to both installation paths.

Before getting started, check [Tested Vacuums](tested_vacuums.md) and [Known Limitations](known_limitations.md) to see if your vacuum model has been tested and that you understand the current limitations of the stack. 

## Prerequisites

- A domain name that you own
- A computer with Wi-Fi capabilities
- A local machine to run the stack on your LAN
- A network that can host the stack's HTTPS and MQTT TLS ports internally. The defaults are `555` and `8881`.
- If you want to use Cloudflare DNS-01 auto-renew (recommended), you will need a Cloudflare API token with DNS edit access for the zone. See [Cloudflare setup](cloudflare_setup.md).

## Common Terms

- The **stack FQDN** is the hostname you choose for this application. It must be a subdomain of a domain you own and it must start with `api-`.
- The **admin password** is used later for signing in to your local server dashboard.
- The **protocol login email and PIN** are the local login that Home Assistant or the Roborock app use after you repoint them to this server.
- Your **Roborock cloud email and verification code** are used only by the admin dashboard's cloud import flow so the local server can fetch your current homes, rooms, routines, and known vacuums.

## Network Setup

1. For the setup you need to own your own domain. If you do not have one, you can register a domain with any domain registrar of your liking. 

   > If you wish to use Cloudflare DNS-01 auto-renew, you will need to set Cloudflares nameservers for your domain.
    
2. Your network **must** handle its own DNS for the network the vacuum connects to. If the vacuum, phone, or onboarding machine uses an external DNS server this will not work. 

   > Local DNS can sometimes be handled by your router, if you don't have a router that supports local DNS, you can use a local DNS server like [Pi-hole](https://pi-hole.net/) or [AdGuard Home](https://adguard.com/en/adguard-home/overview.html) or any other of your choice.
   
   > Cloudflare DNS-01 certificate issuance will not require public inbound access, public port forwarding, or Cloudflare proxying. So there is no need to expose the stack to the internet.

   > Some users may want to expose the stack publicly. For this cases the server does support authentication, and can disable new device pairing. Make sure you understand the security implications before doing so.

3. In your local DNS, create a subdomain entry starting with `api-` for the `stack FQDN` and point it to the LAN IP of the machine you are planning to run the stack on. 
   > Onboarding has a hard 32-character limit for the final `host[:port]/` value sent to the vacuum after the `api-` prefix is stripped. Use a short subdomain to avoid hitting that limit. For example:
   >
   > - `api-rr.example.com` with the default port becomes `rr.example.com:555/` and fits.
   > - `api-roborock-local-server.example.com` with the default port becomes `roborock-local-server.example.com:555/` and is too long.

4. From an another client on the same network open a terminal and verify the name resolves to the server's IP address:

   ```bash
   nslookup api-roborock.example.com
   ```

   For the first setup and onboarding flow, your home network clients should resolve this name to the server's LAN IP. 
   > With the default server behavior, the same hostname is advertised for both HTTPS and MQTT/TLS, so you do not need a separate `mqtt-...` hostname unless you have built your own custom client routing around one.

   > If a reverse proxy maps public ports to different backend listener ports, see [Reverse Proxy](reverse_proxy.md) before starting the stack.

## Installation
### Choose Your Certificate Path First
Different vacuums trust different certificate chains. That determines whether you should:

- use `zerossl` with Cloudflare DNS-01 automation,
- use `actalis` with Cloudflare DNS-01 automation, or
- skip Cloudflare ACME and [bring your own certificate files instead](custom_cert_management.md)

You can check [Tested Vacuums](tested_vacuums.md) to see of anyone has already tested your vacuum model with a specific certificate chain. For most users, prefer `zerossl` authority.  The `actalis` is mainly used by older vacuums or for models that already have been tested showing better compatibility with that chain.

If your model already has certificate notes on the tested-vacuums page, follow that guidance first. It is easier to choose the right certificate path up front than to reissue certs after onboarding starts.

Now you are ready to install the stack. There are two installation paths. Pick one and follow the steps for that path:

### Installation Paths
* [Docker Compose](docker_compose.md) for a standalone Docker deployment
* [Home Assistant](home_assistant.md) for installing as Home Assistant app (add-on). 



If you chose Cloudflare DNS-01 auto-renew, it may take a few minutes for the certificate to be issued. If the page does not load after a few minutes, check that the DNS resolves correctly and the stack is running: 

## After The Stack Starts

### Test your installation
To test your installation, open a browser and go to your admin dashboard at `https://api-roborock.example.com:555/admin`. You should see the admin dashboard login page.

If the page does not load, check if the DNS resolves correctly and the stack is running: 
   * For Docker Compose, check with:
      ```bash
         docker compose ps #check if the stack is running
         docker compose logs -f roborock-local-server #check the logs for errors
      ```
   * For the Home Assistant app, check if the server has status `running` in the Apps section and then check the **logs** tab.

> If you chose Cloudflare DNS-01 auto-renew, it may take a few minutes for the certificate to be issued and the stack to start.


### Sync your Roborock cloud data with the local stack

After either Docker or Home Assistant stack is running, you can log in to the admin dashboard and import your Roborock cloud data.

1. Open your admin dashboard at `https://api-roborock.example.com:555/admin`.

2. Log in to the interface with admin password you have configured. Under cloud import, enter your Roborock cloud email, select **Send code**, then enter the code sent to your email and select **Fetch data**.

3. For any routines that use zones, re-save them so the server stores the zone data correctly. In the Roborock app, open each routine that has zones, open the zone, tap **Edit**, open any **Zone Cleaning** entry, then tap **Save**. Repeat for each zone in the routine.


## Pair a vacuum to the local stack
After everything is set up, continue with [Onboarding](onboarding.md) to pair a vacuum.