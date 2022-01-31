Name: tarantool-acme-client
Version: 2.0.0
Release: 1%{?dist}
Summary: Lua module ACME(v2)-client for Tarantool
Group: Applications/Databases
License: BSD
URL: https://github.com/a1div0/acme-client
Source0: acme-client-%{version}.tar.gz
BuildArch: noarch
BuildRequires: tarantool-devel >= 1.6.8.0
Requires: tarantool >= 1.6.8.0

%description
Lua module ACME(v2)-client for Tarantool

%prep
%setup -q -n acme-client-%{version}

%check
./test/acme-client.test.lua

%install
# Create /usr/share/tarantool/acme-client
mkdir -p %{buildroot}%{_datadir}/tarantool/acme-client
# Copy init.lua to /usr/share/tarantool/acme-client/init.lua
cp -p luakit/*.lua %{buildroot}%{_datadir}/tarantool/acme-client

%files
%dir %{_datadir}/tarantool/acme-client
%{_datadir}/tarantool/acme-client/
%doc README.md
%{!?_licensedir:%global license %doc}
%license LICENSE AUTHORS

%changelog
* Mon Jan 31 2022 Alexander Klenov <a.a.klenov@ya.ru> 2.0.0-1
* Tue Jan 18 2022 Alexander Klenov <a.a.klenov@ya.ru> 1.0.0-1
- Initial version of the RPM spec
