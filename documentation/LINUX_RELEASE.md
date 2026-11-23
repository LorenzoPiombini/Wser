# Install Wser on Linux

The `wser` package contains the standalone HTTP/HTTPS server in `/usr/bin/wser`.
The first binary release targets x86-64 on Ubuntu 24.04 LTS, Debian 13 and
Fedora 44. Installation leaves starting the server and configuring its hostname
and certificates to the administrator.

## Install by package name

Wser's chosen package URL is `https://lorenzopiombini.github.io/Wser/packages/`.
The following commands apply once the maintainer has published the first signed
snapshot. It contains `wser.asc`, `apt/` and `rpm/`.

Download the public key as an ordinary user and compare its primary fingerprint
with the owner's fingerprint before installing it.

```sh
curl -fSLo wser.asc https://lorenzopiombini.github.io/Wser/packages/wser.asc
gpg --show-keys --fingerprint wser.asc
```

**Debian 13 and Ubuntu 24.04 LTS**

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 wser.asc /etc/apt/keyrings/wser.asc
```

Save the following in `/etc/apt/sources.list.d/wser.sources`. The `./` suite
selects the flat APT repository.

```text
Types: deb
URIs: https://lorenzopiombini.github.io/Wser/packages/apt/
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

Save the following in `/etc/yum.repos.d/wser.repo`.

```ini
[wser]
name=Wser
baseurl=https://lorenzopiombini.github.io/Wser/packages/rpm/
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
package directly, use its local filename. For v0.1.0 the commands are
`sudo apt install ./wser_0.1.0-1_amd64.deb` and
`sudo dnf install ./wser-0.1.0-1.x86_64.rpm`.

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
`createrepo-c`. If this is the first release, create the signing key on the
maintainer's computer, choose a passphrase at the prompt and keep a secure
backup. Copy the full primary fingerprint from the second command.

```sh
gpg --quick-generate-key 'Wser package releases' rsa3072 sign 2y
gpg --list-secret-keys --fingerprint 'Wser package releases'
```

Set `WSER_SIGNING_FINGERPRINT` to that fingerprint. The final argument is a
new directory under an existing parent. Supply the paths to both packages.

```sh
packaging/build-repo.sh "$WSER_SIGNING_FINGERPRINT" \
  /path/to/wser_0.1.0-1_amd64.deb /path/to/wser-0.1.0-1.x86_64.rpm \
  /path/to/new-snapshot
```

The script signs APT's `Release` file, the RPM package and DNF's `repomd.xml`.
Only public material is in the completed snapshot. Keep the private signing
key on the signing host. Distribute its public fingerprint to users through
a trusted channel.

### Publish to GitHub Pages

In the GitHub repository settings, choose **Pages → Deploy from a branch →
gh-pages → / (root)**. From a separate checkout of `gh-pages`, copy the
contents of the signed snapshot into `packages/` and publish in one commit.
The `downloads/` directory holds the original release artifacts.

```sh
mkdir -p packages
cp -a /path/to/new-snapshot/. packages/
touch .nojekyll
git add -- .nojekyll packages/
git commit -m 'Publish signed Wser package repository'
git push origin HEAD:gh-pages
```

After Pages finishes deploying, check that both signed indexes are reachable.

```sh
curl -fsSI https://lorenzopiombini.github.io/Wser/packages/apt/InRelease
curl -fsSI https://lorenzopiombini.github.io/Wser/packages/rpm/repodata/repomd.xml.asc
```

For upgrades, use the same signing key and publish each complete snapshot
under the same `packages/` path.
