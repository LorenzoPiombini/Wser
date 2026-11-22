# Install Wser on Linux

The `wser` package contains the standalone HTTP/HTTPS server in `/usr/bin/wser`.
The first binary release targets x86-64 on Ubuntu 24.04 LTS, Debian 13 and
Fedora 44. Installation leaves starting the server and configuring its hostname
and certificates to the administrator.

## Install by package name

Use the HTTPS base URL and the full signing-key fingerprint supplied by the
repository owner. The server publishes `wser.asc`, `apt/` and `rpm/` under
that URL. The examples use `packages.example.org` as a placeholder.

Download the public key as an ordinary user and compare its primary fingerprint
with the owner's fingerprint before installing it.

```sh
curl -fSLo wser.asc https://packages.example.org/wser/wser.asc
gpg --show-keys --fingerprint wser.asc
```

**Debian 13 and Ubuntu 24.04 LTS**

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 wser.asc /etc/apt/keyrings/wser.asc
```

Save the following in `/etc/apt/sources.list.d/wser.sources`, substituting
the repository's URL. The `./` suite selects the flat APT repository.

```text
Types: deb
URIs: https://packages.example.org/wser/apt/
Suites: ./
Architectures: amd64
Signed-By: /etc/apt/keyrings/wser.asc
```

```sh
sudo apt update
sudo apt install wser
dpkg-query -W wser
```

**Fedora 44**

```sh
sudo install -m 0644 wser.asc /etc/pki/rpm-gpg/RPM-GPG-KEY-wser
```

Save the following in `/etc/yum.repos.d/wser.repo`, substituting the
repository's URL.

```ini
[wser]
name=Wser
baseurl=https://packages.example.org/wser/rpm/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-wser
```

```sh
sudo dnf install wser
rpm -q wser
```

APT and DNF check this source for future upgrades. To install a downloaded
package directly, pass its local path to `sudo apt install ./wser_…_amd64.deb`
or `sudo dnf install ./wser-….x86_64.rpm`.

## Run the server

For a local HTTP test, run `wser` as an ordinary user. It creates `www/` and
`.wser.conf` under that account's home directory. Use the port printed on
startup. For example, if it prints `8080`, open `http://localhost:8080/`.

For systemd and Certbot, follow the [TLS deployment guide](CERTBOT_AUTOMATIC_RENEWAL.md)
and use `/usr/bin/wser` in `ExecStart` when running the packaged binary.

Two upstream behaviors matter when evaluating v0.1.0. The HTTPS static-file
handler labels plain files as gzip, which can cause browsers to reject pages.
In HTTPS mode the default HTTP redirect also points to `lorenzopiombini.com`.

## Build v0.1.0

Use the source archive `wser-0.1.0.tar.gz`. The DEB and RPM recipes package
the default server and resolve runtime dependencies from its linked binary.

On Debian or Ubuntu install `build-essential debhelper libssl-dev`, unpack
the archive, enter its top-level directory and run the following. The binary
package is written to the parent directory.

```sh
dpkg-buildpackage -b -us -uc
```

On Fedora install `gcc make openssl-devel rpm-build redhat-rpm-config` and run
this command as an ordinary user from the directory containing the archive.

```sh
rpmbuild -ta wser-0.1.0.tar.gz
```

## Sign and host a repository

The hosting service only needs to serve static files over HTTPS. On the signing
machine install GnuPG, `dpkg-dev`, `apt-utils`, `rpm` (including `rpmsign`) and
`createrepo-c`. Use a release signing key that the publisher can retain for
future upgrades. The final argument is a new directory under an existing
parent. Supply the actual paths to the two packages.

```sh
packaging/build-repo.sh "$WSER_SIGNING_FINGERPRINT" \
  /path/to/wser_0.1.0-1_amd64.deb /path/to/wser-0.1.0-1.x86_64.rpm \
  /path/to/new-snapshot
```

The script signs APT's `Release` file, the RPM package and DNF's `repomd.xml`.
It prints the completed snapshot directory. Publish its contents under one
stable URL, and distribute the public fingerprint through a trusted channel.
For upgrades, build the new snapshot separately, then switch the hosted
directory to the complete snapshot. Keep the signing key on the signing host.
