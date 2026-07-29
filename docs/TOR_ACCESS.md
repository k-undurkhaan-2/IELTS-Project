# Tor Access

This document is the public-safe access policy for the intended maintainer-operated IELTMPS Hosted Service. It is not a deployment guide and does not verify that a public service is currently live.

## Recommended client

**Tor Browser: Recommended by the IELTMPS Project for its intended Hosted Service**

Tor Browser is the client that the IELTMPS Project recommends and intends to support for its maintainer-operated Hosted Service once that service is launched. Users should obtain Tor Browser from the Tor Project through a channel they trust and keep it updated.

The support statement applies to the public business layer only. It does not publish or authorize access to administration, authentication, backend, or internal services.

## Business onion address

**Business onion address: Not yet published**

Do not rely on guessed addresses, screenshots, search results, unsolicited messages, or addresses copied from unofficial services.

The repository does not currently publish a business-layer service address. Tracked Tor configuration is not proof that a public deployment is live or available.

## No public clearnet endpoint

No public clearnet IELTMPS Hosted Service endpoint is currently published.

Source code, issue discussions, and public project documentation may remain available through ordinary development platforms such as GitHub. Availability of project materials on the clearnet does not create or imply a clearnet application service.

A third party may independently operate its own deployment. That deployment is not the IELTMPS Hosted Service unless it is identified through maintainer-controlled trusted channels.

## Third-party integrations

Third-party Tor-capable browsers, extensions, proxy integrations, gateways, and embedded clients may work technically, but they are:

- **Unsupported**
- **Not privacy-equivalent to Tor Browser**
- **Used at the user’s own risk**

IELTMPS does not recommend a specific extension, gateway, proxy product, or alternate browser. Such tools may change DNS behavior, proxy only part of a session, expose browser identifiers, mishandle isolation, or apply a different update and security model.

A tool reaching the same service does not make its privacy properties equivalent to Tor Browser.

## Address verification

When the business address is eventually published, users should verify it through both:

1. A signed release announcement.
2. Another maintainer-controlled trusted channel.

The second channel should be independent enough to help detect account compromise or address substitution. The project should document the signing identity, rotation process, correction process, and trusted publication locations before launch.

An address should not be treated as verified merely because it appears in source code, a fork, a search result, or a third-party directory.

## Security limitations

The Tor network can reduce direct network-location exposure, but it does not make every client, account, browser extension, operating system, content workflow, or server deployment secure.

Users should consider:

- Account identifiers and information they submit.
- Files they download or open outside Tor Browser.
- Browser modifications and extensions.
- Reuse of identities across services.
- Device compromise and local logging.
- Phishing and address substitution.
- The privacy and retention policy of the service operator.

Tracked business, administration, and authentication separation is implementation evidence. Live production operation and public-service security have not been verified.

Detailed deployment and operational guidance remains pending security-owner review. Public documentation will not include internal topology, private network addresses, hidden-service keys, client-auth material, untracked overlays, or non-public service addresses.

## Source-repository availability

The public source repository and public project documentation may be distributed through ordinary development platforms and mirrors. This supports review, self-hosting, source availability, and resilience.

A source mirror is not automatically an authorized service endpoint. Users should independently verify software releases, applicable licenses, notices, and the eventual business address through maintainer-controlled channels.

For the current readiness classification, see [Development Status](STATUS.md).
