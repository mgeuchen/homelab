# USAGE
# - label two attached partitions storage-0 and backup-0
# - create /mnt/backup-0
# - ensure pi/smb/shared exists on storage-0
# - generate nixos hardware config with 'nixos-generate-config' before replacing with this config
# - create secrets as expected
# - add nixos-hardware channel before rebuilding
# - configure ssh key to access cloud backup (see BORG_RSH)
# - initialize borg cache by e.g. executing 'borg list <repo>' on repositories

{ config, pkgs, ... }:
let
  # directories should be owned by root (`drwx--x--x  2 root root`)
  # files should be owned by root (`-rw-------  1 root root`)
  secrets = {
    smb = "/etc/secrets/smp.passphrase";
    borg-cloud = "/etc/secrets/borg-cloud.passphrase";
    user-pi = "/etc/secrets/user-pi.passphrase.hash"; # generate value with `mkpasswd -m yescrypt "<your-password>"`

    # files must be owned by systemd-network (`-rw------- 1 systemd-network systemd-network`)
    wireguard = {
      cloudlink = {
        privKey = "/etc/secrets/wireguard/cloudlink.private";
        psk = "/etc/secrets/wireguard/pi-cloudgate.psk";
      };
      vpn = {
        privKey = "/etc/secrets/wireguard/vpn.private";
        psk = {
          mgePhone = "/etc/secrets/wireguard/pi-mgephone.psk";
        };
      };
    };
  };
  prod = import ./prod.conf.nix;

  wireguardCloudlinkInterface = "wg1";
  wireguardVpnInterface = "wg0";
  username = "pi";
  hostname = "raspberrypi";
  BORG_RSH = "ssh -i /root/.ssh/cloud_backup";
  commonBackupArgs = {
    paths = [ "/home" "/root" "/etc/nixos" ];
    exclude = [ "/home/*/.cache" "/root/.config/borg/security" ];
    compression = "lz4";
    doInit = true;
    startAt = [ "*-*-* 02:00:00" ];
    user = "root";
    prune.keep = {
      within = "1d";
      daily = 7;
      weekly = 4;
      monthly = 12;
    };
    extraCreateArgs = "--exclude-caches --one-file-system -v --stats";
    extraPruneArgs = "-v --list";
    postInit = "echo Started backup $(date)...";
    postCreate = "echo Finished backup $(date).";
    postPrune = "echo Finished pruning backup $(date).";
  };

  # backup failure notifications
  borgbackupMonitor = { config, pkgs, lib, ... }: with lib; {
    key = "borgbackupMonitor";
    _file = "borgbackupMonitor";
    config.systemd.services = {
      "failure-notification@" = {
        enable = true;
        serviceConfig.User = "root";
        environment.SERVICE = "%i";
        script = ''
          ${pkgs.curl}/bin/curl -H "Authorization: Bearer $(cat /etc/secrets/ntfy.token)" -d "$SERVICE failed!" https://ntfy.zeroducks.de/pi
        '';
      };
    } // flip mapAttrs' config.services.borgbackup.jobs (name: value:
      nameValuePair "borgbackup-job-${name}" {
        unitConfig.OnFailure = "failure-notification@%i.service";
      }
    );
  };

in

{
  hardware = {
    raspberry-pi."4".apply-overlays-dtmerge.enable = true;
    deviceTree = {
      enable = true;
      filter = "*rpi-4-*.dtb";
    };
  };
  boot.loader.generic-extlinux-compatible.enable = true;
  boot.kernelParams = [ "cgroup_enable=memory" "cgroup_enable=cpuset" "cgroup_memory=1" ]; # for k3s

  imports = [
    <nixos-hardware/raspberry-pi/4>
    ./hardware-configuration.nix
    borgbackupMonitor
  ];

  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  # Use the GRUB 2 boot loader. (for testing in vm, following two lines)
  # boot.loader.grub.enable = true;
  # boot.loader.grub.device = "/dev/sda"; # or "nodev" for efi only

  # boot.loader.grub.efiSupport = true;
  # boot.loader.grub.efiInstallAsRemovable = true;
  # boot.loader.efi.efiSysMountPoint = "/boot/efi";
  # Define on which hard drive you want to install Grub.

  fileSystems."/mnt/backup-0" = {
    device = "/dev/disk/by-label/backup-0";
    fsType = "ext4";
  };

  fileSystems."/home" = {
    device = "/dev/disk/by-label/storage-0";
    fsType = "ext4";
  };

  networking.hostName = hostname; # Define your hostname.
  networking.hosts = {
    "${prod.cloudgate.ip}" = ["cloudgate.internal"];
    "${prod.cloudgate.ip6}" = ["cloudgate.internal"];
  };

  networking.useNetworkd = true;
  services.resolved.enable = true;
  networking.useDHCP = false;
  # Pick only one of the below networking options.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.
  # networking.networkmanager.enable = true;  # Easiest to use and most distros use this by default.

  # Set your time zone.
  time.timeZone = "Europe/Berlin";

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Select internationalisation properties.
  # i18n.defaultLocale = "en_US.UTF-8";
  console.keyMap = "de";
  
  # Enable CUPS to print documents.
  # services.printing.enable = true;

  # Enable sound.
  # sound.enable = true;
  # hardware.pulseaudio.enable = true;

  system.autoUpgrade = {
    enable = true;
    allowReboot = true;
    dates = "Sat *-*-* 04:00:00";
    rebootWindow = {
      lower = "03:00";
      upper = "05:00";
    };
  };

  virtualisation = {
    containers.enable = true;
    podman = {
      enable = true;
      dockerCompat = true; # `docker` alias for podman
      defaultNetwork.settings.dns_enabled = true; # required for containers to talk to each other
    };
  };

  users.mutableUsers = false;

  # disable root login
  users.users.root.hashedPassword = "!";
  
  users.users.${username} = {
    uid = 1000;
    isNormalUser = true;
    extraGroups = [ "wheel" "${username}" ];
    hashedPasswordFile = secrets.user-pi;
    openssh.authorizedKeys.keys = prod.authorizedSshPubKeys;
  };

  users.groups.${username} = {
    gid = 1000;
  };

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    libraspberrypi
    raspberrypi-eeprom
    docker-compose
    firewalld
    tcpdump
    k9s
    htop
  ];
  environment.sessionVariables = {
    BACKUP_CLOUD_SSH="${BORG_RSH} ${prod.cloud-backup.user}@${prod.cloud-backup.host} -p ${prod.cloud-backup.port}";
    BORG_RSH=BORG_RSH;
    BACKUP_CLOUD_REPO="ssh://${prod.cloud-backup.user}@${prod.cloud-backup.host}:${prod.cloud-backup.port}${prod.cloud-backup.repoPath}";
  };

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.

  services.openssh = {
    enable = true;
    settings = {
      # permit password login to avoid lockout in case of pc failure
      # PasswordAuthentication = false;
      # KbdInteractiveAuthentication = false;
      PermitRootLogin = "no";
    };
  };

  # samba

  services.samba-wsdd = {
    enable = true; # make shares visible for windows 10 clients
    interface = "end0";
  };

  services.samba = {
    enable = true;
    openFirewall = true;
    settings = {
      global = {
        "workgroup" = "WORKGROUP";
        "log file" = "/var/log/samba/log.%m";
        "max log size" = "1000";
        "logging" = "file";
        "map to guest" = "bad user";
        "bind interfaces only" = "yes";
        "interfaces" = "end0";
      };
      "shared" = { # this is the name of the share
        path = "/home/pi/smb/shared";
        "read only" = "no";
        browseable = "yes";
      };
    };
  };

  # samba user password (FIXME anakin, this is not the nix way!)
  
  system.activationScripts.sambaUserSetup.text = ''
    (cat ${secrets.smb}; cat ${secrets.smb}) | ${pkgs.samba}/bin/smbpasswd -s -a ${username}
  '';

  services.borgbackup.jobs."local-backup" = commonBackupArgs // {
    repo = "/mnt/backup-0/borg-backup";
    encryption.mode = "none";
  };

  services.borgbackup.jobs."cloud-backup" = commonBackupArgs // {
    repo = "ssh://${prod.cloud-backup.user}@${prod.cloud-backup.host}:${prod.cloud-backup.port}${prod.cloud-backup.repoPath}";
    environment = { BORG_RSH=BORG_RSH; };
    encryption = {
      mode = "repokey";
      passCommand = "cat ${secrets.borg-cloud}";
    };
  };

  services.k3s = {
    enable = true;
    role = "server";
    extraFlags = [
      "--bind-address 10.0.0.100"
      "--advertise-address 10.0.0.100"
      "--node-ip 10.0.0.100"
      "--tls-san 10.0.0.100"
      "--disable=traefik"
    ];
  };

  
  systemd.network = {
    enable = true;

    # cloudlink interface
    netdevs."10-${wireguardCloudlinkInterface}" = {
      netdevConfig = {
        Kind = "wireguard";
        Name = wireguardCloudlinkInterface;
        MTUBytes = "1420";
      };
      wireguardConfig = {
        PrivateKeyFile = secrets.wireguard.cloudlink.privKey;
      };
      wireguardPeers = [
        {
          PublicKey = prod.wireguardPubKeys.cloudgate;
          PresharedKeyFile = secrets.wireguard.cloudlink.psk;
          AllowedIPs = [ "0.0.0.0/0" "::/0" ]; # Accept all source IPs from cloudgate.
          Endpoint = "cloudgate.internal:51820";
          PersistentKeepalive = 10; # Send keepalives every X seconds to keep NAT tables alive. (25 seconds should suffice, but don't)
        }
      ];
    };

    # vpn interface
    netdevs."10-${wireguardVpnInterface}" = {
      netdevConfig = {
        Kind = "wireguard";
        Name = wireguardVpnInterface;
        MTUBytes = "1340";
      };
      wireguardConfig = {
        ListenPort = 51820;
        PrivateKeyFile = secrets.wireguard.vpn.privKey;
      };
      wireguardPeers = [
        {
          PublicKey = prod.wireguardPubKeys.mgePhone;
          PresharedKeyFile = secrets.wireguard.vpn.psk.mgePhone;
          AllowedIPs = [ "10.0.2.2" ];
        }
      ];
    };

    # cloudlink routing
    networks."10-${wireguardCloudlinkInterface}" = {
      matchConfig.Name = wireguardCloudlinkInterface;
      address = ["10.0.1.2/24" "fd3d:c446:5d3f::2/64"];
      routes = [
        {
          Destination = "0.0.0.0/0";
          Gateway = "10.0.1.1";
        }
        {
          Destination = "::/0";
          Gateway = "fd3d:c446:5d3f::1";
        }
      ];
    };

    # vpn routing
    networks."10-${wireguardVpnInterface}" = {
      matchConfig.Name = wireguardVpnInterface;
      address = ["10.0.2.1/24"];
    };

    # lan routing
    networks."10-end0" = {
      matchConfig.Name = "end0";
      address = ["10.0.0.100/24" "fe80::2/64"];
      networkConfig = {
        DHCP = "ipv6";
      };
      ipv6AcceptRAConfig = {
        UseGateway = "no";
      };
      routes = [
        {
          Destination = prod.cloudgate.ip;
          Gateway = "10.0.0.1";
        }
        {
          Destination = prod.cloudgate.ip6;
          Gateway = "fe80::1";
        }
      ];
    };
  };

  networking.firewall.enable = false;
  # networking.firewall.allowPing = true;

  # Use firewalld as our firewall
  systemd.services.firewalld = {
    description = "firewalld - dynamic firewall daemon";
    before = [ "network-pre.target" ];
    wants = [ "network-pre.target" ];
    after = [ "dbus.service" ];
    conflicts = [ "iptables.service" "ip6tables.service" "ebtables.service" "ipset.service" ];
    documentation = [ "man:firewalld(1)" ];
    wantedBy    = [ "multi-user.target" ];
    aliases = [ "dbus-org.fedoraproject.FirewallD1.service" ];
    serviceConfig = {
      ExecStart = "${pkgs.firewalld}/bin/firewalld --nofork --nopid";
      ExecStartPost = "${pkgs.firewalld}/bin/firewall-cmd --state";
      SuccessExitStatus= "251";
      ExecReload = "${pkgs.util-linux} -HUP $MAINPID";
      StandardOutput = "null";
      StandardError = "null";
      Type = "dbus";
      BusName = "org.fedoraproject.FirewallD1";
      KillMode = "mixed";
      DevicePolicy = "closed";
      KeyringMode = "private";
      LockPersonality = "yes";
      MemoryDenyWriteExecute = "yes";
      PrivateDevices = "yes";
      ProtectClock = "yes";
      ProtectControlGroups = "yes";
      ProtectHome = "yes";
      ProtectHostname = "yes";
      ProtectKernelLogs = "yes";
      ProtectKernelModules = "no";
      ProtectKernelTunables = "no";
      ProtectSystem = "yes";
      RestrictRealtime = "yes";
      RestrictSUIDSGID = "yes";
      SystemCallArchitectures = "native";
    };
  };

  # Configure firewall
  environment.etc = {
    "firewalld/firewalld.conf" = {
      mode = "0644";
      text = ''
        DefaultZone=public
        CleanupOnExit=yes
        CleanupModulesOnExit=no
        IPv6_rpfilter=strict
        IndividualCalls=no
        LogDenied=off
        FirewallBackend=nftables
        FlushAllOnReload=yes
        ReloadPolicy=INPUT:DROP,FORWARD:DROP,OUTPUT:DROP
        RFC3964_IPv4=yes

        # Allow container orchestrators to expose ports without explicit configuration in firewalld
        # to play nicely with k8s (klipper service load balancer).
        StrictForwardPorts=no

        NftablesFlowtable=off
        NftablesCounters=no
        NftablesTableOwner=yes
      '';
    };

    "firewalld/zones/public.xml" = {
      mode = "0644";
      text = ''
        <?xml version="1.0" encoding="utf-8"?>
        <zone>
          <short>Public</short>
          <description>
            Public zone holds all interfaces we do not trust. While the traffic arriving on ${wireguardCloudlinkInterface} already is behind a firewall on cloudgate,
            the cloud-provider hosting cloudgate could send packets destined to arbitrary ports. Hence, we filter traffic arriving from cloudgate here again.
            Only selected incoming connections are accepted.
          </description>

          <interface name="end0"/>
          <interface name="${wireguardCloudlinkInterface}"/>

          <service name="wireguard"/>
          <!-- k8s adds global port-forward rules for load balancer services (e.g., ports 80/443) -->
        </zone>
      '';
    };

    "firewalld/zones/internal.xml" = {
      mode = "0644";
      text = ''
        <?xml version="1.0" encoding="utf-8"?>
        <zone>
          <short>Internal</short>
          <description>For use on internal networks. You mostly trust the other computers on the networks to not harm your computer. Only selected incoming connections are accepted.</description>
          
          <source address="10.0.0.0/24"/>
          <source address="10.0.2.0/24"/>
          
          <service name="ssh"/>
          <service name="samba"/>
          <service name="dhcpv6-client"/>
          <port port="6443" protocol="tcp"/> <!-- kubernets API server -->
          
          <forward/>
        </zone>
      '';
    };

    "firewalld/zones/dmz.xml" = {
      mode = "0644";
      text = ''
        <?xml version="1.0" encoding="utf-8"?>
        <zone>
          <short>DMZ</short>
          <description>For computers in your demilitarized zone that are publicly-accessible with limited access to your internal network. Only selected incoming connections are accepted.</description>
          
          <source address="10.42.0.0/16"/> <!-- k3s pods -->
          <source address="10.43.0.0/16"/> <!-- k3s services -->
          
          <rule family="ipv4">
            <destination address="10.42.0.0/16"/> <!-- k3s pods -->
            <accept/>
          </rule>
          <rule family="ipv4">
            <destination address="10.43.0.0/16"/> <!-- k3s services -->
            <accept/>
          </rule>
          <rule family="ipv4">
            <destination address="10.0.0.100/32"/>
            <port port="6443" protocol="tcp"/> <!-- kubernets API server -->
            <accept/>
          </rule>
          <rule family="ipv4">
            <destination address="10.0.0.100/32"/>
            <port port="10250" protocol="tcp"/> <!-- kubelet API -->
            <accept/>
          </rule>
          <rule family="ipv4">
            <destination address="10.0.0.100/32"/>
            <port port="10256" protocol="tcp"/> <!-- kube-proxy -->
            <accept/>
          </rule>
          <rule family="ipv4">
            <destination address="10.0.0.100/32"/>
            <port port="9100" protocol="tcp"/> <!-- node-exporter -->
            <accept/>
          </rule>

          <forward/>
        </zone>
      '';
    };

    "firewalld/policies/dmz-to-public.xml" = {
      mode = "0644";
      text = ''
        <?xml version="1.0" encoding="utf-8"?>
        <policy target="ACCEPT"> <!-- outgoing traffic from k3s (e.g., DNS queries) -->
          <ingress-zone name="dmz"/>
          <egress-zone name="public"/>
        </policy>
      '';
    };
  };

  # Copy the NixOS configuration file and link it from the resulting system
  # (/run/current-system/configuration.nix). This is useful in case you
  # accidentally delete configuration.nix.
  # system.copySystemConfiguration = true;

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It's perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "23.05"; # Did you read the comment?

}

