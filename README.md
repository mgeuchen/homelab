# Homelab Overview

This repository holds configuration for my homelab setup.
The main purpose of my homelab is storing files and creating incremental backups.
For energy efficiency, it runs on a Raspberry PI 4 with 4 GB of RAM.


## Operating System

As on operating system, we are using NixOS for its declarative configuration and ease of rolling back failed updates.


## File Server

For file serving, the homelab hosts a simple samba share on the private network.
For historic reasons, the samba server runs as a systemd unit.


## Backup Strategy

The backup has two main goals:
1. It must preven data loss in case of localised data corruption.
2. It must provide a way of restoring files deleted by accident within a small timeframe.

Given that the backup stores irreplaceable data of potentially high sentimental value (wedding photos, etc.), the backup should provide resilience against data loss not only in case of individual hard drive failures, but also in case of larger geographic events like fires or floods.
This implies, that we will need some form of geo-redundancy.

In practice, we implement this by creating two independent incremental backups: One on a separate hard drive attached to the Pi, the other off-site in *the cloud*. <!-- TODO mention cloud provider and why we chose it -->

Accidental file deletion rarely goes unnoticed for long.
Therefore, a retention period of one week usually suffices.

Concretely, we opted for a fairly standard backup pruning strategy:
We keep
- all backups created within the last 24 hours,
- one backup for each of the last 7 days,
- one backup for each of the last 4 weeks, as well as
- one backup for each year.


### Technical Implementation

To create incremental backups, we utilize BorgBackup in a systemd unit triggered by a timer each day in the early morning (as to not interfere with other network traffic).
BorgBackup encrypts the off-site backup on the client side for privacy.

For our off-site backup in **the cloud**, we went with Hetzner's StorageBox.
While it cannot compete with other cloud storage options for storage cost (at about 5€/month for 1TB, 15€/month for 5TB), we chose it for its predictable cost.
Included in the price is both unlimited in- and out-bound traffic.
The latter is oftentimes surprisingly expensive, getting in the way of regularly testing the backup.

The local backup is written to a separate hard drive attached to the Pi (not the same hard drive that stores the live data for the file server, etc.).
This yields a total of at least three copies of each piece of life data on three seperate media, in two separate locations (which is also quite standard).

## Networking

Our networking setup should support remote access to the Pi's services via a VPN from outside our home network.
Additionally, it should enable hosting public HTTPS services, so we can host our own web-sites, but also alerting services like Ntfy.

Like most home networks, ours has a dynamic IPv4 address, as well as a dynamic IPv6 /64 subnet, which makes remote access slightly more inconvenient.

One option to get around this is using dynamic DNS.
However, that would expose our home network's IP address as the endpoint for HTTPS services, opening our home network up to DoS attacks.
While we can live with our remote services being unavailabe, our home network's internet service should not be impaired.

A common option is to use services like CloudFlare Tunnel.
However, we neither want to be dependent on a cloud provider's proprietary service, nor do we want our traffic to unencryptedly pass through a network we do not trust (like CloudFlare's).

Instead, we opted for setting up an IP layer (to support various transport- and application-layer protocols) reverse proxy on a cheap VPS using NAT and NAT66.
This gives us several properties:
1. We get a static IPv4 and IPv6 address we can use to reach the Pi from the internet,
2. we do not need to expose the home network's IP address ranges to users of our services,
3. the Pi still gets to see the IP address of the client, allowing us to use software like Fail2Ban,.

This setup still requires connectivity between the Pi and the VPS (which we will refer to as *Cloudgate*).
We implemented this using an encrypted tunnel initiated and kept alive by the Pi.
In doing so,
1. we do not need to fiddle with the home network's NAT forwarding rules, and
2. we ensure that our services can only be accessed via Cloudgate.

The latter gives us a first instance (Cloudgate) to block unwanted traffic using a firewall (more on that later).

Note that this tunnel (lets call it Cloudlink) only serves to provide connectivity between the Pi and Cloudgate.
Traffic should not pass through an untrusted network unencryptedly, so this tunne is not directly part of the VPN we use to access the Pi remotely.
For that, our remote devices establish an encrypted tunnel directly with the Pi via Cloudlink.

### Technical Implementation

We configure network addresses, subnets, and routes using networkd.
For their ease of use, we selected firewalld as our firewall, as well as Wireguard for encrypted tunnels.

```
+-----------------+    +-----------------+    +--------------------------------------------------------------+
| Phone           |    | Cloudgate       |    | Pi                                                           |
|                 |    |                 |    |  +-----------------+  +-----------------------------------+  |
|                 |    |                 |    |  | public zone     |  | internal zone                     |  |
| +-------------+ |    | +-------------+ |    |  | +-------------+ |  | +-------------+ +---------------+ |  |
| | 10.0.2.2/24 | |    | | 10.0.1.1/24 +-----------+ 10.0.1.2/24 | |  | | 10.0.2.1/24 | | 10.0.0.100/24 | |  |
| |             | |    | |          Wireguard Cloudlink          | |  | |             | |               | |  |
| |             +-------------------------------------------------------+             | |               | |  |
| |                                    Wireguard VPN                                  | |               | |  |
| |             +-------------------------------------------------------+             | |               | |  |
| |             | |    | |             +-----------+             | |  | |             | |               | |  |
| +-------------+ |    | +-------------+ |    |  | +-------------+ |  | +-------------+ +---------------+ |  |
|                 |    |                 |    |  +-----------------+  +-----------------------------------+  |
+-----------------+    +-----------------+    +--------------------------------------------------------------+
```

## Secrets Management

Until I find a decent way to manage secrets consistently, I should probably just document how to generate each secret and where to put it.
- DNS Token for ACME `kubectl -n prod create secret generic dns-api-token --from-literal=token=<dns-provider-api-token>`
- password hashes for OS users, etc. `mkpasswd -m yescrypt`
- password hashes for ntfy users, etc. `mkpasswd -m bcrypt`
- NTFY auth `kubectl -n prod create secret generic ntfy-auth --from-literal='users=mage:<bcrypt-password-hash>:user' --from-literal='tokens=mage:tk_<29-random-chars>'`

There are two kinds of secrets: those that are generated externally and those that are generated internally.
Externally managed secrets will always have to be managed manually.
Internally managed secrets could be automatically generated, stored, and distributed.
1. Generation is easily automated via scripts.
2. Storage ideally happens in a secrets manager, but that needs to be setup somehow as well.
3. Distribution oftentimes means placing them in a file at some specific location on device (could be done via Ansible in many cases) or in a Kubernetes secret (could be done via a kubectl command or REST call).