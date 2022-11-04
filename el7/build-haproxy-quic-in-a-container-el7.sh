#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

umask 022

LDFLAGS='-Wl,-z,relro -Wl,--as-needed -Wl,-z,now'
export LDFLAGS

CC=gcc
export CC
CXX=g++
export CXX
/sbin/ldconfig

set -e

if ! grep -q -i '^1:.*docker' /proc/1/cgroup; then
    echo
    echo ' Not in a container!'
    echo
    exit 1
fi

_tmp_dir="$(mktemp -d)"
cd "${_tmp_dir}"

rm -fr /tmp/zlib /tmp/openssl /tmp/pcre2 /tmp/glibc /tmp/lua /tmp/haproxy

_zlib_ver="$(wget -qO- 'https://www.zlib.net/' | grep -i 'HREF="zlib-[0-9].*\.tar\.' | sed 's|"|\n|g' | grep '^zlib-' | grep -ivE 'alpha|beta|rc' | sed -e 's|zlib-||g' -e 's|\.tar.*||g' | sort -V | uniq | tail -n 1)"
_lua_ver="$(wget -qO- 'https://www.lua.org/ftp/' | grep -i '<a href' | sed 's/"/ /g' | sed 's/ /\n/g' | grep -i '^lua-[1-9].*\.tar\.gz$' | sed -e 's|lua-||g' -e 's|\.tar.*||g' | sort -V | tail -n 1)"
_pcre2_ver="$(wget -qO- 'https://github.com/PCRE2Project/pcre2/releases' | grep -i 'pcre2-[1-9]' | sed 's|"|\n|g' | grep -i '^/PCRE2Project/pcre2/tree' | sed 's|.*/pcre2-||g' | sed 's|\.tar.*||g' | grep -ivE 'alpha|beta|rc' | sort -V | uniq | tail -n 1)"
_haproxy_path="$(wget -qO- 'https://www.haproxy.org/' | grep -i 'src/haproxy-' | sed 's/"/\n/g' | grep '^/download/' | grep -i '\.gz$' | sort -V | uniq | tail -n 1)"
_haproxy_ver=$(echo ${_haproxy_path} | sed 's|/|\n|g' | grep '^haproxy-[1-9]' | sed -e 's|haproxy-||g' -e 's|\.tar.*||g')

wget -c -t 9 -T 9 "https://zlib.net/zlib-${_zlib_ver}.tar.xz"
wget -c -t 9 -T 9 "https://www.lua.org/ftp/lua-${_lua_ver}.tar.gz"
wget -c -t 9 -T 9 "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${_pcre2_ver}/pcre2-${_pcre2_ver}.tar.bz2"
wget -c -t 9 -T 9 "https://www.haproxy.org${_haproxy_path}"

tar -xof zlib-*.tar.xz
tar -xof "lua-${_lua_ver}.tar.gz"
tar -xof "pcre2-${_pcre2_ver}.tar.bz2"
tar -xof "haproxy-${_haproxy_ver}.tar.gz"
sleep 1
rm -f *.tar*

cd zlib-*
#./configure --64 --static --prefix=/usr --libdir=/usr/lib64 --sysconfdir=/etc
./configure --64 --static --prefix=/usr/local --libdir=/usr/local/lib64
make all -j2
sleep 1
make install
sleep 1
cd ..
rm -fr zlib-*

rm -fr openssl
_branch=$(wget -qO- 'https://github.com/quictls/openssl/branches/all/' | grep -i 'branch="OpenSSL_1_1_1[a-z]+quic"' | sed 's/"/\n/g' | grep -i '^openssl.*quic$' | sort -V | tail -n 1)
_openssl_quic_ver=$(echo "${_branch}" | tr 'A-Z' 'a-z' | sed 's/_1_1_1/-1.1.1/g' | sed 's|+|-|g' | sed 's|openssl-||g')
git clone -b "${_branch}" 'https://github.com/quictls/openssl.git'
sleep 2
cd openssl
rm -fr .git
sleep 2
./Configure \
--prefix=/usr \
--libdir=/usr/lib64 \
--openssldir=/etc/pki/tls \
enable-tls1_3 threads no-shared \
enable-camellia enable-seed enable-rfc3779 \
enable-sctp enable-cms enable-md2 enable-rc5 \
no-mdc2 no-ec2m \
no-sm2 no-sm3 no-sm4 \
enable-ec_nistp_64_gcc_128 linux-x86_64 \
'-DDEVRANDOM="\"/dev/urandom\""'
sleep 1
sed 's@engines-81.1.1@engines@g' -i Makefile
make all 
rm -fr /usr/include/openssl
sleep 1
make install_sw
sleep 1
cd ..
rm -fr openssl*

cd "pcre2-${_pcre2_ver}"
./configure \
--build=x86_64-linux-gnu \
--host=x86_64-linux-gnu \
--disable-shared \
--enable-static \
--enable-pcre2-8 \
--enable-pcre2-16 \
--enable-pcre2-32 \
--enable-jit \
--enable-pcre2grep-libz \
--enable-pcre2grep-libbz2 \
--enable-pcre2test-libedit \
--enable-unicode \
--prefix=/usr --libdir=/usr/lib64 --sysconfdir=/etc
make all -j2
sleep 1
make install
sleep 1
cd ..
rm -fr pcre2-*

cd "lua-${_lua_ver}"
sed 's#INSTALL_TOP=.*#INSTALL_TOP= /usr#g' -i Makefile
sed 's|INSTALL_LIB=.*|INSTALL_LIB= /usr/lib64|g' -i Makefile
sed 's|INSTALL_MAN=.*|INSTALL_MAN= /usr/share/man/man1|g' -i Makefile
make linux
sleep 1
make install
sleep 1
cd ..
rm -fr lua-*

cd "haproxy-${_haproxy_ver}"
sed 's|http://|https://|g' -i include/haproxy/version.h
sed '/DOCDIR =/s@$(PREFIX)/doc@$(PREFIX)/share/doc@g' -i Makefile
sed 's#^PREFIX = /usr.*#PREFIX = /usr#g' -i Makefile
sed 's#^PREFIX = /usr.*#PREFIX = /usr#g' -i admin/systemd/Makefile

rm -f /usr/lib64/*.la
rm -fr /home/.backup
mkdir /home/.backup
sleep 1
cp -af /usr/lib64/libssl.so* /home/.backup/
cp -af /usr/lib64/libcrypto.so* /home/.backup/
cp -af /usr/lib64/libpcre2*.so* /home/.backup/
cp -af /usr/lib64/liblua-*.so* /home/.backup/
sleep 1
#rm -f /usr/lib64/libz.so*
rm -f /usr/lib64/libssl.so*
rm -f /usr/lib64/libcrypto.so*
rm -f /usr/lib64/libpcre2*.so*
rm -f /usr/lib64/liblua-*.so*
rm -f /usr/lib64/liblua.so*

make V=1 -j2 \
CC='gcc' \
CXX='g++' \
CPU=generic \
TARGET=linux-glibc \
USE_PCRE2_JIT=1 \
USE_STATIC_PCRE2=1 \
USE_THREAD=1 \
USE_NS=1 \
USE_QUIC=1 \
USE_OPENSSL=1 \
USE_ZLIB=1 \
USE_TFO=1 \
USE_LUA=1 \
USE_SYSTEMD=1 \
USE_GETADDRINFO=1 \
ZLIB_LIB=/usr/local/lib64 \
ZLIB_INC=/usr/local/include \
ADDLIB="-lz -ldl -pthread" \
LDFLAGS="-Wl,-z,relro -Wl,--as-needed -Wl,-z,now" \
EXTRA_OBJS="addons/promex/service-prometheus.o"

echo
make admin/halog/halog SBINDIR=/usr/bin OPTIMIZE= CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"
for admin in iprange; do
    make -C admin/$admin SBINDIR=/usr/bin OPTIMIZE= CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"
done

echo
for admin in systemd; do
    make -C admin/$admin SBINDIR=/usr/sbin
done

echo
rm -fr /tmp/haproxy*
sleep 2
make DESTDIR=/tmp/haproxy install

install -m 0755 -d /tmp/haproxy/usr/bin
install -m 0755 -d /tmp/haproxy/etc/haproxy/errors
install -m 0755 -d /tmp/haproxy/etc/logrotate.d
install -m 0755 -d /tmp/haproxy/etc/sysconfig
install -m 0755 -d /tmp/haproxy/var/lib/haproxy
install -m 0755 -d /tmp/haproxy/usr/share/doc/haproxy/examples

for admin in halog iprange; do
    install -v -s -c -m 0755 -D admin/$admin/$admin /tmp/haproxy/usr/bin/$admin
done
install -v -s -c -m 0755 admin/iprange/ip6range /tmp/haproxy/usr/bin/
install -v -c -m 0644 admin/systemd/haproxy.service /tmp/haproxy/etc/haproxy/

cp -pfr examples /tmp/haproxy/usr/share/doc/haproxy/
install -c -m 0644 examples/errorfiles/*.http /tmp/haproxy/etc/haproxy/errors/

sleep 2
cd ..
rm -fr "haproxy-${_haproxy_ver}"

cd /tmp/haproxy
find -L usr/share/man/ -type l -exec rm -f '{}' \;
sleep 1
find usr/share/man/ -type f -exec gzip -f -9 '{}' \;
sleep 2
find -L usr/share/man/ -type l | while read file; do ln -svf "$(readlink -s "${file}").gz" "${file}.gz" ; done
sleep 2
find -L usr/share/man/ -type l -exec rm -f '{}' \;
/usr/bin/strip usr/sbin/haproxy

rm -fr etc/logrotate.d/haproxy
rm -fr etc/sysconfig/haproxy
rm -fr etc/haproxy/haproxy.cfg

printf '\x23\x20\x41\x64\x64\x20\x65\x78\x74\x72\x61\x20\x6F\x70\x74\x69\x6F\x6E\x73\x20\x74\x6F\x20\x74\x68\x65\x20\x68\x61\x70\x72\x6F\x78\x79\x20\x64\x61\x65\x6D\x6F\x6E\x20\x68\x65\x72\x65\x2E\x20\x54\x68\x69\x73\x20\x63\x61\x6E\x20\x62\x65\x20\x75\x73\x65\x66\x75\x6C\x20\x66\x6F\x72\x0A\x23\x20\x73\x70\x65\x63\x69\x66\x79\x69\x6E\x67\x20\x6D\x75\x6C\x74\x69\x70\x6C\x65\x20\x63\x6F\x6E\x66\x69\x67\x75\x72\x61\x74\x69\x6F\x6E\x20\x66\x69\x6C\x65\x73\x20\x77\x69\x74\x68\x20\x6D\x75\x6C\x74\x69\x70\x6C\x65\x20\x2D\x66\x20\x6F\x70\x74\x69\x6F\x6E\x73\x2E\x0A\x23\x20\x53\x65\x65\x20\x68\x61\x70\x72\x6F\x78\x79\x28\x31\x29\x20\x66\x6F\x72\x20\x61\x20\x63\x6F\x6D\x70\x6C\x65\x74\x65\x20\x6C\x69\x73\x74\x20\x6F\x66\x20\x6F\x70\x74\x69\x6F\x6E\x73\x2E\x0A\x4F\x50\x54\x49\x4F\x4E\x53\x3D\x22\x22\x0A' | dd seek=$((0x0)) conv=notrunc bs=1 of=etc/sysconfig/haproxy
sleep 1
chmod 0644 etc/sysconfig/haproxy

printf '\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x23\x20\x45\x78\x61\x6D\x70\x6C\x65\x20\x63\x6F\x6E\x66\x69\x67\x75\x72\x61\x74\x69\x6F\x6E\x20\x66\x6F\x72\x20\x61\x20\x70\x6F\x73\x73\x69\x62\x6C\x65\x20\x77\x65\x62\x20\x61\x70\x70\x6C\x69\x63\x61\x74\x69\x6F\x6E\x2E\x20\x20\x53\x65\x65\x20\x74\x68\x65\x0A\x23\x20\x66\x75\x6C\x6C\x20\x63\x6F\x6E\x66\x69\x67\x75\x72\x61\x74\x69\x6F\x6E\x20\x6F\x70\x74\x69\x6F\x6E\x73\x20\x6F\x6E\x6C\x69\x6E\x65\x2E\x0A\x23\x0A\x23\x20\x20\x20\x68\x74\x74\x70\x73\x3A\x2F\x2F\x77\x77\x77\x2E\x68\x61\x70\x72\x6F\x78\x79\x2E\x6F\x72\x67\x2F\x64\x6F\x77\x6E\x6C\x6F\x61\x64\x2F\x32\x2E\x34\x2F\x64\x6F\x63\x2F\x63\x6F\x6E\x66\x69\x67\x75\x72\x61\x74\x69\x6F\x6E\x2E\x74\x78\x74\x0A\x23\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x23\x20\x47\x6C\x6F\x62\x61\x6C\x20\x73\x65\x74\x74\x69\x6E\x67\x73\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x67\x6C\x6F\x62\x61\x6C\x0A\x20\x20\x20\x20\x6C\x6F\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x31\x32\x37\x2E\x30\x2E\x30\x2E\x31\x3A\x35\x31\x34\x20\x6C\x6F\x63\x61\x6C\x30\x20\x69\x6E\x66\x6F\x0A\x20\x20\x20\x20\x63\x68\x72\x6F\x6F\x74\x20\x20\x20\x20\x20\x20\x2F\x76\x61\x72\x2F\x6C\x69\x62\x2F\x68\x61\x70\x72\x6F\x78\x79\x0A\x20\x20\x20\x20\x70\x69\x64\x66\x69\x6C\x65\x20\x20\x20\x20\x20\x2F\x76\x61\x72\x2F\x72\x75\x6E\x2F\x68\x61\x70\x72\x6F\x78\x79\x2E\x70\x69\x64\x0A\x20\x20\x20\x20\x6D\x61\x78\x63\x6F\x6E\x6E\x20\x20\x20\x20\x20\x35\x30\x30\x30\x0A\x20\x20\x20\x20\x75\x73\x65\x72\x20\x20\x20\x20\x20\x20\x20\x20\x68\x61\x70\x72\x6F\x78\x79\x0A\x20\x20\x20\x20\x67\x72\x6F\x75\x70\x20\x20\x20\x20\x20\x20\x20\x68\x61\x70\x72\x6F\x78\x79\x0A\x20\x20\x20\x20\x64\x61\x65\x6D\x6F\x6E\x0A\x0A\x20\x20\x20\x20\x23\x20\x74\x75\x72\x6E\x20\x6F\x6E\x20\x73\x74\x61\x74\x73\x20\x75\x6E\x69\x78\x20\x73\x6F\x63\x6B\x65\x74\x0A\x20\x20\x20\x20\x73\x74\x61\x74\x73\x20\x73\x6F\x63\x6B\x65\x74\x20\x2F\x76\x61\x72\x2F\x6C\x69\x62\x2F\x68\x61\x70\x72\x6F\x78\x79\x2F\x73\x74\x61\x74\x73\x0A\x0A\x20\x20\x20\x20\x23\x20\x75\x74\x69\x6C\x69\x7A\x65\x20\x73\x79\x73\x74\x65\x6D\x2D\x77\x69\x64\x65\x20\x63\x72\x79\x70\x74\x6F\x2D\x70\x6F\x6C\x69\x63\x69\x65\x73\x0A\x20\x20\x20\x20\x73\x73\x6C\x2D\x64\x65\x66\x61\x75\x6C\x74\x2D\x62\x69\x6E\x64\x2D\x63\x69\x70\x68\x65\x72\x73\x20\x50\x52\x4F\x46\x49\x4C\x45\x3D\x53\x59\x53\x54\x45\x4D\x0A\x20\x20\x20\x20\x73\x73\x6C\x2D\x64\x65\x66\x61\x75\x6C\x74\x2D\x73\x65\x72\x76\x65\x72\x2D\x63\x69\x70\x68\x65\x72\x73\x20\x50\x52\x4F\x46\x49\x4C\x45\x3D\x53\x59\x53\x54\x45\x4D\x0A\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x23\x20\x63\x6F\x6D\x6D\x6F\x6E\x20\x64\x65\x66\x61\x75\x6C\x74\x73\x20\x74\x68\x61\x74\x20\x61\x6C\x6C\x20\x74\x68\x65\x20\x27\x6C\x69\x73\x74\x65\x6E\x27\x20\x61\x6E\x64\x20\x27\x62\x61\x63\x6B\x65\x6E\x64\x27\x20\x73\x65\x63\x74\x69\x6F\x6E\x73\x20\x77\x69\x6C\x6C\x0A\x23\x20\x75\x73\x65\x20\x69\x66\x20\x6E\x6F\x74\x20\x64\x65\x73\x69\x67\x6E\x61\x74\x65\x64\x20\x69\x6E\x20\x74\x68\x65\x69\x72\x20\x62\x6C\x6F\x63\x6B\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x64\x65\x66\x61\x75\x6C\x74\x73\x0A\x20\x20\x20\x20\x6D\x6F\x64\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x68\x74\x74\x70\x0A\x20\x20\x20\x20\x6C\x6F\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x67\x6C\x6F\x62\x61\x6C\x0A\x20\x20\x20\x20\x6F\x70\x74\x69\x6F\x6E\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x68\x74\x74\x70\x6C\x6F\x67\x0A\x20\x20\x20\x20\x6F\x70\x74\x69\x6F\x6E\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6F\x6E\x74\x6C\x6F\x67\x6E\x75\x6C\x6C\x0A\x20\x20\x20\x20\x6F\x70\x74\x69\x6F\x6E\x20\x68\x74\x74\x70\x2D\x73\x65\x72\x76\x65\x72\x2D\x63\x6C\x6F\x73\x65\x0A\x20\x20\x20\x20\x6F\x70\x74\x69\x6F\x6E\x20\x66\x6F\x72\x77\x61\x72\x64\x66\x6F\x72\x20\x20\x20\x20\x20\x20\x20\x65\x78\x63\x65\x70\x74\x20\x31\x32\x37\x2E\x30\x2E\x30\x2E\x30\x2F\x38\x0A\x20\x20\x20\x20\x6F\x70\x74\x69\x6F\x6E\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x72\x65\x64\x69\x73\x70\x61\x74\x63\x68\x0A\x20\x20\x20\x20\x72\x65\x74\x72\x69\x65\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x33\x0A\x20\x20\x20\x20\x74\x69\x6D\x65\x6F\x75\x74\x20\x68\x74\x74\x70\x2D\x72\x65\x71\x75\x65\x73\x74\x20\x20\x20\x20\x31\x30\x73\x0A\x20\x20\x20\x20\x74\x69\x6D\x65\x6F\x75\x74\x20\x71\x75\x65\x75\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x31\x6D\x0A\x20\x20\x20\x20\x74\x69\x6D\x65\x6F\x75\x74\x20\x63\x6F\x6E\x6E\x65\x63\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x31\x30\x73\x0A\x20\x20\x20\x20\x74\x69\x6D\x65\x6F\x75\x74\x20\x63\x6C\x69\x65\x6E\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x31\x6D\x0A\x20\x20\x20\x20\x74\x69\x6D\x65\x6F\x75\x74\x20\x73\x65\x72\x76\x65\x72\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x31\x6D\x0A\x20\x20\x20\x20\x74\x69\x6D\x65\x6F\x75\x74\x20\x68\x74\x74\x70\x2D\x6B\x65\x65\x70\x2D\x61\x6C\x69\x76\x65\x20\x31\x30\x73\x0A\x20\x20\x20\x20\x74\x69\x6D\x65\x6F\x75\x74\x20\x63\x68\x65\x63\x6B\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x31\x30\x73\x0A\x20\x20\x20\x20\x6D\x61\x78\x63\x6F\x6E\x6E\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x33\x30\x30\x30\x0A\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x23\x20\x6D\x61\x69\x6E\x20\x66\x72\x6F\x6E\x74\x65\x6E\x64\x20\x77\x68\x69\x63\x68\x20\x70\x72\x6F\x78\x79\x73\x20\x74\x6F\x20\x74\x68\x65\x20\x62\x61\x63\x6B\x65\x6E\x64\x73\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x66\x72\x6F\x6E\x74\x65\x6E\x64\x20\x6D\x61\x69\x6E\x0A\x20\x20\x20\x20\x62\x69\x6E\x64\x20\x2A\x3A\x35\x30\x30\x30\x0A\x20\x20\x20\x20\x61\x63\x6C\x20\x75\x72\x6C\x5F\x73\x74\x61\x74\x69\x63\x20\x20\x20\x20\x20\x20\x20\x70\x61\x74\x68\x5F\x62\x65\x67\x20\x20\x20\x20\x20\x20\x20\x2D\x69\x20\x2F\x73\x74\x61\x74\x69\x63\x20\x2F\x69\x6D\x61\x67\x65\x73\x20\x2F\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x20\x2F\x73\x74\x79\x6C\x65\x73\x68\x65\x65\x74\x73\x0A\x20\x20\x20\x20\x61\x63\x6C\x20\x75\x72\x6C\x5F\x73\x74\x61\x74\x69\x63\x20\x20\x20\x20\x20\x20\x20\x70\x61\x74\x68\x5F\x65\x6E\x64\x20\x20\x20\x20\x20\x20\x20\x2D\x69\x20\x2E\x6A\x70\x67\x20\x2E\x67\x69\x66\x20\x2E\x70\x6E\x67\x20\x2E\x63\x73\x73\x20\x2E\x6A\x73\x0A\x0A\x20\x20\x20\x20\x75\x73\x65\x5F\x62\x61\x63\x6B\x65\x6E\x64\x20\x73\x74\x61\x74\x69\x63\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x66\x20\x75\x72\x6C\x5F\x73\x74\x61\x74\x69\x63\x0A\x20\x20\x20\x20\x64\x65\x66\x61\x75\x6C\x74\x5F\x62\x61\x63\x6B\x65\x6E\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x61\x70\x70\x0A\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x23\x20\x73\x74\x61\x74\x69\x63\x20\x62\x61\x63\x6B\x65\x6E\x64\x20\x66\x6F\x72\x20\x73\x65\x72\x76\x69\x6E\x67\x20\x75\x70\x20\x69\x6D\x61\x67\x65\x73\x2C\x20\x73\x74\x79\x6C\x65\x73\x68\x65\x65\x74\x73\x20\x61\x6E\x64\x20\x73\x75\x63\x68\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x62\x61\x63\x6B\x65\x6E\x64\x20\x73\x74\x61\x74\x69\x63\x0A\x20\x20\x20\x20\x62\x61\x6C\x61\x6E\x63\x65\x20\x20\x20\x20\x20\x72\x6F\x75\x6E\x64\x72\x6F\x62\x69\x6E\x0A\x20\x20\x20\x20\x73\x65\x72\x76\x65\x72\x20\x20\x20\x20\x20\x20\x73\x74\x61\x74\x69\x63\x20\x31\x32\x37\x2E\x30\x2E\x30\x2E\x31\x3A\x34\x33\x33\x31\x20\x63\x68\x65\x63\x6B\x0A\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x23\x20\x72\x6F\x75\x6E\x64\x20\x72\x6F\x62\x69\x6E\x20\x62\x61\x6C\x61\x6E\x63\x69\x6E\x67\x20\x62\x65\x74\x77\x65\x65\x6E\x20\x74\x68\x65\x20\x76\x61\x72\x69\x6F\x75\x73\x20\x62\x61\x63\x6B\x65\x6E\x64\x73\x0A\x23\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x0A\x62\x61\x63\x6B\x65\x6E\x64\x20\x61\x70\x70\x0A\x20\x20\x20\x20\x62\x61\x6C\x61\x6E\x63\x65\x20\x20\x20\x20\x20\x72\x6F\x75\x6E\x64\x72\x6F\x62\x69\x6E\x0A\x20\x20\x20\x20\x73\x65\x72\x76\x65\x72\x20\x20\x61\x70\x70\x31\x20\x31\x32\x37\x2E\x30\x2E\x30\x2E\x31\x3A\x35\x30\x30\x31\x20\x63\x68\x65\x63\x6B\x0A\x20\x20\x20\x20\x73\x65\x72\x76\x65\x72\x20\x20\x61\x70\x70\x32\x20\x31\x32\x37\x2E\x30\x2E\x30\x2E\x31\x3A\x35\x30\x30\x32\x20\x63\x68\x65\x63\x6B\x0A\x20\x20\x20\x20\x73\x65\x72\x76\x65\x72\x20\x20\x61\x70\x70\x33\x20\x31\x32\x37\x2E\x30\x2E\x30\x2E\x31\x3A\x35\x30\x30\x33\x20\x63\x68\x65\x63\x6B\x0A\x20\x20\x20\x20\x73\x65\x72\x76\x65\x72\x20\x20\x61\x70\x70\x34\x20\x31\x32\x37\x2E\x30\x2E\x30\x2E\x31\x3A\x35\x30\x30\x34\x20\x63\x68\x65\x63\x6B\x0A' | dd seek=$((0x0)) conv=notrunc bs=1 of=etc/haproxy/haproxy.cfg
sleep 1
chmod 0644 etc/haproxy/haproxy.cfg

printf '\x0A\x5B\x5B\x20\x2D\x64\x20\x2F\x76\x61\x72\x2F\x6C\x6F\x67\x2F\x68\x61\x70\x72\x6F\x78\x79\x20\x5D\x5D\x20\x7C\x7C\x20\x6D\x6B\x64\x69\x72\x20\x2F\x76\x61\x72\x2F\x6C\x6F\x67\x2F\x68\x61\x70\x72\x6F\x78\x79\x0A\x72\x6D\x20\x2D\x66\x20\x2F\x65\x74\x63\x2F\x72\x73\x79\x73\x6C\x6F\x67\x2E\x64\x2F\x68\x61\x70\x72\x6F\x78\x79\x2E\x63\x6F\x6E\x66\x0A\x65\x63\x68\x6F\x20\x27\x23\x20\x43\x6F\x6C\x6C\x65\x63\x74\x20\x6C\x6F\x67\x20\x77\x69\x74\x68\x20\x55\x44\x50\x0A\x24\x4D\x6F\x64\x4C\x6F\x61\x64\x20\x69\x6D\x75\x64\x70\x0A\x24\x55\x44\x50\x53\x65\x72\x76\x65\x72\x41\x64\x64\x72\x65\x73\x73\x20\x31\x32\x37\x2E\x30\x2E\x30\x2E\x31\x0A\x24\x55\x44\x50\x53\x65\x72\x76\x65\x72\x52\x75\x6E\x20\x35\x31\x34\x0A\x23\x20\x43\x72\x65\x61\x74\x69\x6E\x67\x20\x73\x65\x70\x61\x72\x61\x74\x65\x20\x6C\x6F\x67\x20\x66\x69\x6C\x65\x73\x20\x62\x61\x73\x65\x64\x20\x6F\x6E\x20\x74\x68\x65\x20\x73\x65\x76\x65\x72\x69\x74\x79\x0A\x23\x6C\x6F\x63\x61\x6C\x30\x2E\x2A\x20\x2F\x76\x61\x72\x2F\x6C\x6F\x67\x2F\x68\x61\x70\x72\x6F\x78\x79\x2F\x68\x61\x70\x72\x6F\x78\x79\x2D\x74\x72\x61\x66\x66\x69\x63\x2E\x6C\x6F\x67\x0A\x23\x6C\x6F\x63\x61\x6C\x30\x2E\x6E\x6F\x74\x69\x63\x65\x20\x2F\x76\x61\x72\x2F\x6C\x6F\x67\x2F\x68\x61\x70\x72\x6F\x78\x79\x2F\x68\x61\x70\x72\x6F\x78\x79\x2D\x61\x64\x6D\x69\x6E\x2E\x6C\x6F\x67\x0A\x6C\x6F\x63\x61\x6C\x30\x2E\x2A\x20\x2F\x76\x61\x72\x2F\x6C\x6F\x67\x2F\x68\x61\x70\x72\x6F\x78\x79\x2F\x68\x61\x70\x72\x6F\x78\x79\x2E\x6C\x6F\x67\x0A\x27\x20\x3E\x20\x2F\x65\x74\x63\x2F\x72\x73\x79\x73\x6C\x6F\x67\x2E\x64\x2F\x68\x61\x70\x72\x6F\x78\x79\x2E\x63\x6F\x6E\x66\x0A\x73\x6C\x65\x65\x70\x20\x31\x0A\x63\x68\x6D\x6F\x64\x20\x30\x36\x34\x34\x20\x2F\x65\x74\x63\x2F\x72\x73\x79\x73\x6C\x6F\x67\x2E\x64\x2F\x68\x61\x70\x72\x6F\x78\x79\x2E\x63\x6F\x6E\x66\x0A\x2F\x62\x69\x6E\x2F\x73\x79\x73\x74\x65\x6D\x63\x74\x6C\x20\x73\x74\x6F\x70\x20\x72\x73\x79\x73\x6C\x6F\x67\x2E\x73\x65\x72\x76\x69\x63\x65\x0A\x73\x6C\x65\x65\x70\x20\x32\x0A\x2F\x62\x69\x6E\x2F\x73\x79\x73\x74\x65\x6D\x63\x74\x6C\x20\x73\x74\x61\x72\x74\x20\x72\x73\x79\x73\x6C\x6F\x67\x2E\x73\x65\x72\x76\x69\x63\x65\x0A\x0A' | dd seek=$((0x0)) conv=notrunc bs=1 of=etc/haproxy/.eable-haproxy-log.txt
sleep 1
chmod 0644 etc/haproxy/.eable-haproxy-log.txt

sleep 2
mv -f etc/haproxy/haproxy.cfg etc/haproxy/haproxy.cfg.default

echo '/var/log/haproxy/haproxy.log {
    daily
    rotate 10
    missingok
    notifempty
    compress
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
        /bin/kill -HUP `cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}' > etc/logrotate.d/haproxy
sleep 1
chmod 0644 etc/logrotate.d/haproxy

echo '
cd "$(dirname "$0")"
rm -f /lib/systemd/system/haproxy.service
sleep 1
systemctl daemon-reload >/dev/null 2>&1 || : 
install -v -c -m 0644 haproxy.service /lib/systemd/system/
install -m 0755 -d /var/lib/haproxy
install -m 0755 -d /var/log/haproxy
getent group haproxy >/dev/null || groupadd -r haproxy
getent passwd haproxy >/dev/null || useradd -r -g haproxy \
  -d /var/lib/haproxy -s /usr/sbin/nologin -c "HAProxy Load Balancer" haproxy
sleep 1
chown -R haproxy:haproxy /var/lib/haproxy
chown -R haproxy:haproxy /var/log/haproxy
systemctl daemon-reload >/dev/null 2>&1 || : 
' > etc/haproxy/.install.txt

echo
sleep 2
tar -Jcvf /tmp/"haproxy-${_haproxy_ver}-1.el7.x86_64.tar.xz" *
echo
sleep 2

cp -af /home/.backup/* /usr/lib64/
sleep 1
rm -fr /home/.backup

cd /tmp
sha256sum "haproxy-${_haproxy_ver}-1.el7.x86_64.tar.xz" > "haproxy-${_haproxy_ver}-1.el7.x86_64.tar.xz".sha256
sleep 2
cd /tmp
rm -fr "${_tmp_dir}"
rm -fr /tmp/zlib /tmp/openssl /tmp/pcre2 /tmp/glibc /tmp/lua /tmp/haproxy
echo
echo ' build haproxy done '
echo
/sbin/ldconfig
exit

