#!/bin/sh
# Build an APT and DNF repository snapshot from release packages.
set -eu
umask 022

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 SIGNING_KEY_FINGERPRINT WSER.deb WSER.rpm NEW_OUTPUT_DIR" >&2
    exit 2
fi
key=$1
deb=$(realpath -- "$2")
rpm_file=$(realpath -- "$3")
output=$(realpath -m -- "$4")

case "$key" in ''|*[!0-9A-Fa-f]*) echo 'Expected a full OpenPGP fingerprint' >&2; exit 2 ;; esac
if [ "${#key}" -ne 40 ] && [ "${#key}" -ne 64 ]; then
    echo 'Expected a full OpenPGP fingerprint' >&2
    exit 2
fi
if [ -e "$output" ] || [ -L "$output" ]; then
    echo "Output already exists: $output" >&2
    exit 2
fi
gpg --list-secret-keys "$key" >/dev/null

if [ "$(dpkg-deb -f "$deb" Package)" != wser ] || [ "$(dpkg-deb -f "$deb" Architecture)" != amd64 ] ||
   [ "$(rpm -qp --qf '%{NAME}/%{ARCH}' "$rpm_file")" != wser/x86_64 ]; then
    echo 'Expected Wser amd64 DEB and x86_64 RPM packages' >&2
    exit 2
fi
version=$(dpkg-deb -f "$deb" Version)
if [ "${version%-*}" != "$(rpm -qp --qf '%{VERSION}' "$rpm_file")" ]; then
    echo 'The packages have different upstream versions' >&2
    exit 2
fi

stage=$(mktemp -d "$(dirname -- "$output")/.wser-feed.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$stage/apt" "$stage/rpm"
gpg --armor --export-options export-minimal --export "$key" > "$stage/wser.asc"
install -m 0644 "$deb" "$stage/apt/wser_${version}_amd64.deb"
rpm_name=$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm' "$rpm_file")
install -m 0644 "$rpm_file" "$stage/rpm/$rpm_name"

(
    cd "$stage/apt"
    dpkg-scanpackages . /dev/null > Packages
    gzip -nk Packages
    apt-ftparchive -o APT::FTPArchive::Release::Origin=Wser \
        -o APT::FTPArchive::Release::Label=Wser \
        -o APT::FTPArchive::Release::Architectures=amd64 release . > ../Release
    mv ../Release Release
    gpg --local-user "$key" --clearsign --output InRelease Release
    gpg --local-user "$key" --armor --detach-sign --output Release.gpg Release
)

# rpm 4 uses _gpg_name and rpm 6 uses _openpgp_sign_id.
rpmsign --define "_gpg_name $key" --define "_openpgp_sign_id $key" \
    --addsign "$stage/rpm/$rpm_name"
createrepo_c "$stage/rpm"
gpg --local-user "$key" --armor --detach-sign "$stage/rpm/repodata/repomd.xml"

chmod 0755 "$stage"
mv -Tn -- "$stage" "$output"
if [ -d "$stage" ]; then
    echo "Output created by another build: $output" >&2
    exit 1
fi
trap - EXIT
echo "Package repository ready in $output"
