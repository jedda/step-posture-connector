# Step Posture Connector

Step Posture Connector (`step-posture-connector`) is a middleware tool designed to assist [`step-ca`](https://github.com/smallstep/certificates) with posture information during an ACME device attestation process.

It was originally born to leverage [Managed Device Attestation for Apple devices](https://support.apple.com/en-au/guide/deployment/dep28afbde6a/web) in a [`step-ca`](https://github.com/smallstep/certificates) and Jamf Pro environment as a control to ensure that Apple attested ACME certificates are securely issued to approved, managed and compliant devices. It also supports flat files (JSON, CSV) and plans to incorporate other MDM providers such as Intune, Kandji and Mosyle.

Step Posture Connector utilises the [webhooks](https://smallstep.com/docs/step-ca/webhooks/) functionality within [`step-ca`](https://github.com/smallstep/certificates) to allow/deny and enrich certificates with additional data during the order process.

This project is licensed under the [terms of the MIT license](LICENSE).

## Protection of the device-attest-01 challenge

The `device-attest-01` ACME challenge can pose significant a security risk in production when exposed to the internet without further additional controls in place. Without external account binding or another authorisation method, any device that can satisfy the `device-attest-01` challenge can enroll in your PKI simply by knowing the ACME directory URI. In the case of Apple's Managed Device Attestation – when Apple provides attestation for a device, they are attesting that is is a genuine Apple device with specific identifiers, but not that it belongs to or is assigned to your organisation. Step Posture Connector helps you gatekeep this in a few ways:

- Attested permanent identifiers (UDIDs & serial numbers - see below) are matched against device records to authorise them as a managed device
- Lookups can return enriched data about devices and users that can be included in and further validated by logic within your [`step-ca`](https://github.com/smallstep/certificates) templates
- Optionally; devices can also be required to have membership of a specific compliance group within MDM. In the case of Jamf smart groups, this can be used to require up to date inventory check-in, OS versions, or any other attribute to to gatekeep certificate issuance - see [Compliance Group Membership](https://github.com/jedda/step-posture-connector#compliance-group-membership) below.

See [Usage Philosophy & Considerations](https://github.com/jedda/step-posture-connector#usage-philosophy--considerations) below for more details on using `step-posture-connector` to secure resources or services.

## Providers

Below is the list of currently supported providers and  a brief explanation of what they do:

| Provider | Description |
| --- | ----------- |
| `file` | Reads a local file (JSON, CSV) with device identifiers and optional encrichment data and matches device requests against this list. Great for testing or gatekeeping against a specific static list of devices. |
| `jamf` | Uses the Jamf API to match a device identifiers against an enrolled Mobile Device or Computer. Can use an optional compliance group to gatekeep a subset of devices and can return enrichment data. |

Ideally, next steps will include addition of new providers for posture & data enrichment. Happy to take feedback, but would suggest Intune, Kandji, Mosyle & Addigy as logical next steps.

## Security

`step-posture-connector` supports the following to ensure a secure connection between itself and [`step-ca`](https://github.com/smallstep/certificates):

- TLS version enforcement (v1.2 & above) and modern, secure server cipher suite selection
- HMAC verification of Smallstep request via provided [`step-ca`](https://github.com/smallstep/certificates) headers
- Optional mutual TLS via client certificate verification from [`step-ca`](https://github.com/smallstep/certificates)

## Getting started

I've started creating a [Setup Guide](https://github.com/jedda/step-posture-connector/wiki/Setup-Guide) which should walk you through the steps of setting up `step-posture-connector` and starting to lookup and authorise attested devices. It's currently a little rough around the edges, but should be enough to get you started.

If you'd like to report any security issues, [send me a DM on the MacAdmins slack](https://macadmins.slack.com/team/U1QABUHAR).

## Deployment

### Docker image (reccomended)

Deployment via Docker is probably most simple and reccomended - particularly if you are already [running `step-ca` this way](https://hub.docker.com/r/smallstep/step-ca). All config can be done via environment variables as per the Configuration section below and a [docker-compose file](docker/docker-compose.yml) is included in this repository.

Releases of `step-posture-connector` [are available on Docker Hub as `jedda/step-posture-connector`](https://hub.docker.com/repository/docker/jedda/step-posture-connector).

### Standalone binaries

You can run `step-posture-connector` as a standalone binary. When doing so, configuration is easiest via a .env file in it's working directory or via standard environment variables as per the Configuration section below.

Releases are [available for major platforms as compiled binaries here](https://github.com/jedda/step-posture-connector/releases).

### Building `step-posture-connector`

You can of course choose to download and build your own binaries or docker containers. `step-posture-connector` is [written in Go](https://go.dev/project) and can be run with a simple `go run main.go`.

A [Dockerfile](docker/Dockerfile) is also included should you wish to roll your own container variants.

## Webhooks

Currently, there is a single webhook endpoint supported by `step-posture-connector`:

- `/webhook/device-attest` 

For each webhook you create in [`step-ca`](https://github.com/smallstep/certificates), it will generate and display a `Webhook ID` and `Webhook Secret`. You'll need to supply these using the `WEBHOOK_IDS` and `WEBHOOK_SECRETS` configuration variable below to initialise the webhook for use. For more information on how to do this, see the [Setup Guide](https://github.com/jedda/step-posture-connector/wiki/Setup-Guide).

The webhook endpoint takes an optional `type` query string that may be needed depending what device you are targeting. At the moment this is required only by Jamf, as the API endpoints it uses to search and match iOS devices vs computers is different and `step-posture-connector` must be told which one is being requested. For Jamf, the webhook format should be as follows:

- `/webhook/device-attest?mode=mobiledevice` for iOS devices
- `/webhook/device-attest?mode=computer` for Mac computers

Note that Jamf lookup will default to `mode=mobiledevice` if a mode is not defined, so only `mode=computer` is actually required to specifically target Macs. If you are using Jamf and want to target both iOS and Mac, youll need to create two different provisioners in [`step-ca`](https://github.com/smallstep/certificates) - one for each platform with it's own appropriate webhook pointing at the correct mode.

The file provider ignores the `mode` query and treats every device type as the same.

## Compliance Group Membership

Where supported by the MDM provider, `step-posture-connector` can utilise Compliance Groups to ensure device posture baseline prior to certificate issuance.

This can be used to ensure that devices meet certain compliance criteria before being allowed to order an MDA ACME certificate. With Jamf, you can use a smart group to assess devices and computers against this criteria.

Where a group is defined, `step-posture-connector` will only allow a certificate to be issued if a device is a member of this group, and will deny other requests.


## Configuration

Configuration is performed via environment variables; able to be supplied in the shell, via a .env file or via Docker when using the supplied Docker image (reccomended).`step-posture-connector` will validate configuration on start – including bootstrapping and checking your selected provider (although the error messages arent super friendly or verbose - something to improve on later).

### Global Configuration

| Environment Variable | Required | Description |
| --- |  --- | ----------- |
| `PROVIDER` | required | Specifies which provider to use. Currently needs to be one of `file` or `jamf`. |
| `TLS_CERT_PATH` | required | Specifies the file path of the PEM formatted certificate to use for the webhook server. |
| `TLS_KEY_PATH` | required | Specifies the file path of the private key to use for the webhook server. |
| `WEBHOOK_IDS` | required | Specifies a comma delimited list of `step-ca` webhook IDs. See "Webhooks" for details. |
| `WEBHOOK_SECRETS` | required | Specifies a comma delimited list of `step-ca` webhook secrets (matching the IDs supplied using 	`WEBHOOK_IDS`). See "Webhooks" for details. |
| `ENABLE_MTLS` | optional | Enables mutual TLS (mTLS) for requests to the webhook server. Needs to be `0` or `1`. |
| `TLS_CA_PATH` | required (with `ENABLE_MTLS `) | Specifies the file path of the PEM formatted CA to validate mTLS requests. |
| `PORT` | optional | Specifies which TCP port the HTTPS webserver will start on. Defaults to `9443`. |
| `LOGGING_LEVEL` | optional | Specifies the verbosity level of logging. needs to be one of `0` (allow/deny only), `1` (verbose), or `2` (debug). Defaults to `0`. |
| `TIMEOUT` | optional | A global timeout value used by providers for any HTTPS connections. Defaults to `10`. |

### Provider Configuration - File (`file`)

The following additional configuration variables apply when using the `file` provider.

| Environment Variable | Required | Description |
| --- |  --- | ----------- |
| `FILE_PATH` | required | Specifies the path to a file containing device data. |
| `FILE_TYPE` | required | Specifies the file type. Currently needs to be one of `csv` or `json`. |

### Provider Configuration - Jamf Pro (`jamf`)

The following additional configuration variables apply when using the `jamf` provider. You'll need to [create an appropriate API Role & Client in Jamf](https://learn.jamf.com/bundle/jamf-pro-documentation-current/page/API_Roles_and_Clients.html) to generate the ID and Secret. Role privileges required are `Read Mobile Devices` and `Read Computers` depending on which devices you are targeting.

| Environment Variable | Required | Description |
| --- |  --- | ----------- |
| `JAMF_BASE_URL` | required | Specifies the base URL for your Jamf instance (eg. https://example.jamfcloud.com) |
| `JAMF_CLIENT_ID` | required | Specifies the Jamf API OAuth client ID used to request a bearer token. |
| `JAMF_CLIENT_SECRET` | required | Specifies the Jamf API OAuth client secret used to request a bearer token. |
| `JAMF_DEVICE_GROUP` | optional | When included, specifies a Jamf Mobile Device group to check membership against for iOS devices. |
| `JAMF_COMPUTER_GROUP` | optional | When included, specifies a Jamf Computer group to check membership against for Mac devices. |
| `JAMF_DEVICE_ENRICH` | optional | Specifies if user enrichment data should be returned to `step-ca` for Mobile Devices. Needs to be `0` or `1`. Defaults to `0`. |
| `JAMF_COMPUTER_ENRICH` | optional | Specifies if user enrichment data should be returned to `step-ca` for Computers. Needs to be `0` or `1`. Defaults to `0`.|

## Usage Philosophy & Considerations

When using this tool, it's important to consider the security concepts of identification, authentication and authorisation and how they apply to any resources being accessed with issued certificates. 

I've [written about this in further depth as part of a technical explortation into Managed Attestation for Apple devices](https://jedda.me/managed-device-attestation-a-technical-exploration/) which is worth a read if you want to better understand the concepts.

How you use the device attestation certificates facilitated by [`step-ca`](https://github.com/smallstep/certificates) and Step Posture Connector is entirely up to you, however 802.1x & VPN (& mTLS on iOS) are the obvious usage candidates. For the most part, certificates enriched with a user identity can identify a user and even stand in as an authentication method, but they likely don't authorise a user against specific services nor attest to the current status of that user. Where possible, take care to validate the certificate and any user identity SANs during consumption by services to ensure user posture alongside that of the device.


### iOS vs macOS Use Cases

Due to differences in how keychains are implemented on iOS vs macOS, there are currently some significant differences in how hardware bound certficates can be utilised on each platform.

On macOS, the issued cert gets stored in the data protection keychain which means it's not available in Keychain Access or even using the `security ` command. MDM can get details of the cert by using the `CertificateList` command, but browsers won't see it (so no mTLS) and on-device posture clients (such as Cloudflare WARP, Zscaler, ect) won't see it  so can't be used to evidence device posture.	This really limits the usage of the certificate to the config profile it ships in, and likely to 801.1x and VPN payloads for the time being. Hopefully we see this change in future versions of macOS to allow for powerful mTLS & device posture flows into ZTNA, ect.

On iOS this is a slightly better story, as the issued cert is stored in the Apple keychain access group which makes it available to Safari (and other Apple apps) for use as an mTLS client certificate as well as the profile payloads (801.1x and VPN) available on macOS.

### Attested Device Permanent Identifiers

Under my testing in the current implementations of Managed Device Attestation on macOS devices (Apple Silicon & Intel with T2, Sonoma 14.1), the following are returned as permanent identifier options by Apple's attestation servers:

- Device Serial Number
- Device Provisioning UDID

Note that this "Device Provisioning UDID" is not the "Hardware UUID" (or UDID as reported to some MDMs), but instead the "Device Provisioning UDID" (viewable in macOS System Information/Report) which is not by default captured by MDM.

When using MDM providers for matching, this means the Device Provisioning UDID isn't really a suitable candidate as a matching identifier, so for Jamf we currently support Device Serial Number only. I can't find a lot of documentation on this, so if i'm wrong here or there is a better way I'd love to be pointed in a better direction.

## Questions, Issues & Discussions

Feel free to [start a discussion](https://github.com/jedda/step-posture-connector/discussions) or [create an issue](https://github.com/jedda/step-posture-connector/issues). You are also welcome to [DM me on the Mac Admins Slack](https://macadmins.slack.com/team/U1QABUHAR).
