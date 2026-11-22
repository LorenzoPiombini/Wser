Name:           wser
Version:        0.1.0
Release:        1%{?dist}
Summary:        HTTP/1.1 web server for Linux with TLS support
License:        Apache-2.0
URL:            https://github.com/LorenzoPiombini/Wser
Source0:        %{name}-%{version}.tar.gz
ExclusiveArch:  x86_64

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  openssl-devel >= 3.0

%description
Wser serves static files using epoll and OpenSSL. It supports HTTP and
HTTPS listeners and can serve Certbot's HTTP-01 challenges.

%prep
%setup -q

%build
%make_build wser CC=gcc CFLAGS="-Iinclude -std=gnu17 %{optflags}" RELEASE_CFLAGS= LDFLAGS="%{?build_ldflags}"

%install
make install-server DESTDIR="%{buildroot}" bindir="%{_bindir}"

%files
%license LICENSE
%doc README.md documentation/CERTBOT_AUTOMATIC_RENEWAL.md documentation/LINUX_RELEASE.md
%{_bindir}/wser
