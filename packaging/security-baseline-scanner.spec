Name:           security-baseline-scanner
Version:        1.0.0
Release:        1%{?dist}
Summary:        Conservative read-only Linux security baseline observations
License:        MIT
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  gcc-c++
BuildRequires:  cmake >= 3.16
BuildRequires:  make
BuildRequires:  python3

%description
Inspect bounded local security evidence and generate text, JSON and Markdown
reports. No network access, telemetry, remediation or numerical security score.

%prep
%autosetup

%build
%cmake -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release
%cmake_build

%check
%ctest

%install
%cmake_install

%files
%license LICENSE
%{_bindir}/security-baseline-scanner
%{_mandir}/man1/security-baseline-scanner.1*
%{_docdir}/security-baseline-scanner/

%changelog
* Tue Sep 15 2026 GuhsHosting <guhshosting@users.noreply.github.com> - 1.0.0-1
- Initial release.
