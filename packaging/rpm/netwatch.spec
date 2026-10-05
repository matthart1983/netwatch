# RPM spec for Fedora COPR.
#
# This builds netwatch *from source* against the system libpcap, which is what
# a distro repository is expected to ship — unlike the `.rpm` attached to each
# GitHub release, which repackages the musl-static binary and depends on
# nothing. Both exist on purpose: the release rpm installs anywhere, this one
# is a normal Fedora package.
#
# COPR builds it via its SCM source method (see docs/PACKAGING.md), so `Version`
# below must match Cargo.toml. `spec_version_matches_the_crate` in
# tests/packaging.rs fails the build if they drift.
Name:           netwatch
Version:        0.35.3
Release:        1%{?dist}
Summary:        Real-time network diagnostics in your terminal

License:        MIT
URL:            https://github.com/matthart1983/netwatch
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  libpcap-devel
# Defines %{_unitdir}; without it the %files list fails with
# "File must begin with /" on an unexpanded macro.
BuildRequires:  systemd-rpm-macros
Requires:       libpcap

%description
Live per-connection throughput with application-protocol decoding, process
attribution where the platform allows it, packet and interface views, and a
diagnostic engine that learns a per-network baseline and opens an issue when
that baseline breaks. Runs in a terminal and needs no configuration.

Packet capture needs elevated access: run netwatch with sudo, or grant the
capabilities once with
  setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' %{_bindir}/netwatch

%prep
%autosetup -n %{name}-%{version}

%build
# Not %%cargo_build: that macro expects the vendored-dependency layout Fedora
# uses for packages in the main repository. COPR builders have network access,
# so an ordinary cargo build against Cargo.lock is both simpler and exactly
# what upstream CI tests.
cargo build --release --locked

%install
install -Dpm0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}
install -Dpm0644 docs/%{name}.1 %{buildroot}%{_mandir}/man1/%{name}.1
install -Dpm0644 completions/%{name}.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/%{name}
install -Dpm0644 completions/_%{name} \
    %{buildroot}%{_datadir}/zsh/site-functions/_%{name}
install -Dpm0644 completions/%{name}.fish \
    %{buildroot}%{_datadir}/fish/vendor_completions.d/%{name}.fish
install -Dpm0644 packaging/systemd/%{name}.service \
    %{buildroot}%{_unitdir}/%{name}.service

%post
# Deliberately does not run setcap — granting a binary raw-socket access is
# the administrator's decision. See packaging/debian/postinst.
cat <<'MSG'

netwatch is installed. Packet capture needs elevated access:

  sudo netwatch                       # works as-is, or grant it once:
  sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /usr/bin/netwatch

Capabilities attach to the file, so re-apply after each upgrade.

MSG

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/%{name}
%{_mandir}/man1/%{name}.1*
%{_datadir}/bash-completion/completions/%{name}
%{_datadir}/zsh/site-functions/_%{name}
%{_datadir}/fish/vendor_completions.d/%{name}.fish
%{_unitdir}/%{name}.service

%changelog
* Mon Oct 05 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.35.3-1
- FreeBSD interface up-state from IFF_UP

* Sun Oct 04 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.35.2-1
- FreeBSD binary builds on 13.5 and runs on 13+

* Sat Oct 03 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.35.1-1
- Fix a flaky CI test and the spec version left behind in 0.35.0 (never published)

* Sat Oct 03 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.35.0-1
- FreeBSD support: interfaces, routes, process attribution, clipboard, and sockstat-based connections

* Thu Oct 01 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.34.0-1
- Diagnose issues expire and close when they should, Observations, schema 2

* Tue Sep 29 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.33.0-1
- Diagnose abstains on missing inputs, and a health lab tests the engine end to end

* Sun Sep 27 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.32.5-1
- 0.32.4 with its macOS test fixed

* Sun Sep 27 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.32.4-1
- terminal escapes, attacker-driven memory, capture panics, owner-only exports

* Sun Sep 20 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.32.3-1
- Diagnostic evidence rules, eBPF under the sandbox, and the RPM spec bumped
  with the crate

* Sun Sep 20 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.32.1-1
- Packaging release: deb/rpm, container image, completions and man page

* Sun Sep 20 2026 Matt Hartley <matthew.t.hartley@gmail.com> - 0.32.0-1
- Initial COPR package
