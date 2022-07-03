#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

umask 022

bash /opt/gcc/set-shared-libstdcxx >/dev/null 2>&1

CFLAGS='-O2 -fexceptions -g -grecord-gcc-switches -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -fstack-protector-strong -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection'
export CFLAGS
CXXFLAGS='-O2 -fexceptions -g -grecord-gcc-switches -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -fstack-protector-strong -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection'
export CXXFLAGS
LDFLAGS='-Wl,-z,relro -Wl,--as-needed -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld'
export LDFLAGS

_SAVED_LDFLAGS="${LDFLAGS}"
LDFLAGS="${_SAVED_LDFLAGS} -Wl,-rpath,/usr/lib64/nginx/private"
export LDFLAGS

CC=gcc
export CC
CXX=g++
export CXX
/sbin/ldconfig

yum makecache
yum install -y glibc-devel glibc-headers libxml2-devel libxslt-devel gd-devel perl-devel perl bc

set -e

if ! grep -q -i '^1:.*docker' /proc/1/cgroup; then
    echo
    echo ' Not in a container!'
    echo
    exit 1
fi

_dl_nginx() {
    set -e
    wget -c -t 9 -T 9 'https://hg.nginx.org/nginx/archive/tip.tar.gz'
    sleep 1
    tar -xf tip.tar.gz
    sleep 1
    rm -f tip.tar.gz
    #mv -f nginx-* nginx
    # zlib
    _zlib_ver="$(wget -qO- 'https://www.zlib.net/' | grep -i 'HREF="zlib-[0-9].*\.tar\.' | sed 's|"|\n|g' | grep '^zlib-' | grep -ivE 'alpha|beta|rc' | sed -e 's|zlib-||g' -e 's|\.tar.*||g' | sort -V | uniq | tail -n 1)"
    wget -c -t 9 -T 9 "https://zlib.net/zlib-${_zlib_ver}.tar.xz"
    sleep 1
    tar -xf  zlib-*.tar.xz
    sleep 1
    rm -f zlib-*.tar*
    mv -f zlib-* zlib
    # openssl 1.1.1
    _openssl_111_ver="$(wget -qO- 'https://www.openssl.org/source/' | grep 'a href="openssl-1.1.1' | sed 's|"|\n|g' | grep -i '^openssl-1.1.1' | grep -ivE '\.sha|\.asc' | sed -e 's|openssl-||g' -e 's|\.tar.*||g')"
    wget -c -t 9 -T 9 "https://www.openssl.org/source/openssl-${_openssl_111_ver}.tar.gz"
    sleep 1
    tar -xf openssl-${_openssl_111_ver}.tar.gz
    sleep 1
    rm -f openssl-*.tar*
    mv -f openssl-* openssl
    # pcre2
    _pcre2_ver="$(wget -qO- 'https://github.com/PCRE2Project/pcre2/releases' | grep -i 'pcre2-.*.tar.bz2' | sed 's|"|\n|g' | grep -i '^/PCRE2Project/pcre2/releases/download' | sed 's|.*/pcre2-||g' | sed 's|\.tar.*||g' | grep -ivE 'alpha|beta|rc' | sort -V | uniq | tail -n 1)"
    wget -c -t 9 -T 9 "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${_pcre2_ver}/pcre2-${_pcre2_ver}.tar.bz2"
    sleep 1
    tar -xf pcre2-${_pcre2_ver}.tar.*
    sleep 1
    rm -f pcre2-*.tar*
    mv -f pcre2-* pcre2

    # modules
    install -m 0755 -d modules && cd modules
    git clone "https://github.com/nbs-system/naxsi.git" \
      ngx_http_naxsi_module
    git clone "https://github.com/nginx-modules/ngx_cache_purge.git" \
      ngx_http_cache_purge_module
    git clone "https://github.com/arut/nginx-rtmp-module.git" \
      ngx_rtmp_module
    git clone "https://github.com/leev/ngx_http_geoip2_module.git" \
      ngx_http_geoip2_module
    git clone "https://github.com/openresty/headers-more-nginx-module.git" \
      ngx_http_headers_more_filter_module
    git clone "https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git" \
      ngx_http_substitutions_filter_module
    git clone --recursive "https://github.com/eustas/ngx_brotli.git" \
      ngx_http_brotli_module
    git clone "https://github.com/apache/incubator-pagespeed-ngx.git" \
      ngx_pagespeed
      wget -c "https://dl.google.com/dl/page-speed/psol/1.13.35.2-x64.tar.gz" -O psol.tar.gz
      sleep 1
      tar -xf psol.tar.gz -C ngx_pagespeed/
      sleep 1
      rm -fr psol.tar.gz
    git clone "https://github.com/openresty/redis2-nginx-module.git" \
      ngx_http_redis2_module
    git clone "https://github.com/openresty/memc-nginx-module.git" \
      ngx_http_memc_module
    git clone "https://github.com/openresty/echo-nginx-module.git" \
      ngx_http_echo_module
    cd ..

    install -m 0755 -d geoip2 && cd geoip2
    _license_key='uzrU0s2GJt6I'
    for _edition_id in GeoLite2-ASN GeoLite2-Country GeoLite2-City; do
        wget -c -t 9 -T 9 -O "${_edition_id}.tar.gz" "https://download.maxmind.com/app/geoip_download?edition_id=${_edition_id}&license_key=${_license_key}&suffix=tar.gz"
    done
    sleep 2
    ls -1 *.tar* | xargs -I '{}' tar -xf '{}'
    sleep 2
    rm -f *.tar*
    find ./ -mindepth 2 -type f -iname '*.mmdb' | xargs -I '{}' cp -f '{}' ./
    sleep 2
    find ./ -mindepth 1 -type d | xargs -I '{}' rm -fr '{}'
    cd ..

}


_build_libmaxminddb() {
    set -e
    cd /tmp
    _tmp_dir="$(mktemp -d)"
    cd "${_tmp_dir}"
    git clone --recursive 'https://github.com/maxmind/libmaxminddb.git' libmaxminddb
    cd libmaxminddb
    rm -fr .git
    rm -f ltmain.sh && bash bootstrap
    ./configure \
    --build=x86_64-linux-gnu --host=x86_64-linux-gnu \
    --enable-shared --enable-static \
    --prefix=/usr --libdir=/usr/lib64 --includedir=/usr/include --sysconfdir=/etc
    sleep 1
    make all -j1
    rm -fr /tmp/libmaxminddb
    make install DESTDIR=/tmp/libmaxminddb
    cd /tmp/libmaxminddb
    find usr/ -type f -iname '*.la' -delete
    if [[ -d usr/sbin ]]; then
        file usr/sbin/* | sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | xargs -I '{}' /usr/bin/strip '{}'
    fi
    if [[ -d usr/bin ]]; then
        file usr/bin/* | sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | xargs -I '{}' /usr/bin/strip '{}'
    fi
    if [[ -d usr/lib/x86_64-linux-gnu ]]; then
        find usr/lib/x86_64-linux-gnu/ -iname 'lib*.so*' -type f -exec /usr/bin/strip "{}" \;
        find usr/lib/x86_64-linux-gnu/ -iname '*.so' -type f -exec /usr/bin/strip "{}" \;
    elif [[ -d usr/lib64/ ]]; then
        find usr/lib64/ -iname 'lib*.so*' -type f -exec /usr/bin/strip "{}" \;
        find usr/lib64/ -iname '*.so' -type f -exec /usr/bin/strip "{}" \;
    fi
    if [[ -d usr/share/man ]]; then
        find -L usr/share/man/ -type l -exec rm -f '{}' \;
        find usr/share/man/ -type f -iname '*.[1-9]' -exec gzip -f -9 '{}' \;
        sleep 2
        find -L usr/share/man/ -type l | while read file; do ln -svf "$(readlink -s "${file}").gz" "${file}.gz" ; done
        sleep 2
        find -L usr/share/man/ -type l -exec rm -f '{}' \;
    fi
    echo
    sleep 2
    tar -Jcvf /tmp/libmaxminddb-git-1.el7.x86_64.tar.xz *
    echo
    sleep 2
    cd /tmp
    rm -fr "${_tmp_dir}"
    rm -fr /tmp/libmaxminddb
}
_build_brotli() {
    set -e
    cd /tmp
    _tmp_dir="$(mktemp -d)"
    cd "${_tmp_dir}"
    git clone --recursive 'https://github.com/google/brotli.git' brotli
    cd brotli
    rm -fr .git
    bash bootstrap
    ./configure \
    --build=x86_64-linux-gnu --host=x86_64-linux-gnu \
    --enable-shared --enable-static \
    --prefix=/usr --libdir=/usr/lib64 --includedir=/usr/include --sysconfdir=/etc
    sleep 1
    make all -j2
    rm -fr /tmp/brotli
    make install DESTDIR=/tmp/brotli
    cd /tmp/brotli
    find usr/ -type f -iname '*.la' -delete
    if [[ -d usr/sbin ]]; then
        file usr/sbin/* | sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | xargs -I '{}' /usr/bin/strip '{}'
    fi
    if [[ -d usr/bin ]]; then
        file usr/bin/* | sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | xargs -I '{}' /usr/bin/strip '{}'
    fi
    if [[ -d usr/lib/x86_64-linux-gnu ]]; then
        find usr/lib/x86_64-linux-gnu/ -iname 'lib*.so*' -type f -exec /usr/bin/strip "{}" \;
        find usr/lib/x86_64-linux-gnu/ -iname '*.so' -type f -exec /usr/bin/strip "{}" \;
    elif [[ -d usr/lib64/ ]]; then
        find usr/lib64/ -iname 'lib*.so*' -type f -exec /usr/bin/strip "{}" \;
        find usr/lib64/ -iname '*.so' -type f -exec /usr/bin/strip "{}" \;
    fi
    if [[ -d usr/share/man ]]; then
        find -L usr/share/man/ -type l -exec rm -f '{}' \;
        find usr/share/man/ -type f -iname '*.[1-9]' -exec gzip -f -9 '{}' \;
        sleep 2
        find -L usr/share/man/ -type l | while read file; do ln -svf "$(readlink -s "${file}").gz" "${file}.gz" ; done
        sleep 2
        find -L usr/share/man/ -type l -exec rm -f '{}' \;
    fi
    echo
    sleep 2
    tar -Jcvf /tmp/brotli-git-1.el7.x86_64.tar.xz *
    echo
    sleep 2
    cd /tmp
    rm -fr "${_tmp_dir}"
    rm -fr /tmp/brotli
}

_build_libmaxminddb
_build_brotli
tar -xf /tmp/libmaxminddb-*.el7.x86_64.tar.xz -C /
tar -xf /tmp/brotli-*.el7.x86_64.tar.xz -C /
sleep 1
/sbin/ldconfig >/dev/null 2>&1
rm -f /tmp/libmaxminddb-*.el7.x86_64.tar.xz /tmp/brotli-*.el7.x86_64.tar.xz

_tmp_dir="$(mktemp -d)"
cd "${_tmp_dir}"

_dl_nginx

cd nginx-*
getent group nginx >/dev/null || groupadd -r nginx
getent passwd nginx >/dev/null || useradd -r -d /var/lib/nginx -g nginx -s /usr/sbin/nologin -c "Nginx web server" nginx
############################################################################
_vmajor=4
_vminor=7
_vpatch=1
_longver=$(printf "%1d%03d%03d" ${_vmajor} ${_vminor} ${_vpatch})
_fullver="$(echo \"${_vmajor}\.${_vminor}\.${_vpatch}\")"
sed "s@#define nginx_version.*@#define nginx_version      ${_longver}@g" -i src/core/nginx.h
sed "s@#define NGINX_VERSION.*@#define NGINX_VERSION      ${_fullver}@g" -i src/core/nginx.h
sed 's@"nginx/"@"gws-v"@g' -i src/core/nginx.h
sed 's@Server: nginx@Server: gws@g' -i src/http/ngx_http_header_filter_module.c
sed 's@<hr><center>nginx</center>@<hr><center>gws</center>@g' -i src/http/ngx_http_special_response.c
############################################################################
sed 's@\./config --prefix=$ngx_prefix@& no-rc2 no-rc4 no-rc5 no-sm2 no-sm3 no-sm4 enable-tls1_3@g' -i auto/lib/openssl/make
sleep 1
cat auto/lib/openssl/make
_http_module_args="$(./auto/configure --help | grep -i '\--with-http' | awk '{print $1}' | sed 's/^[ ]*//g' | sed 's/[ ]*$//g' | grep -v '=' | sort -u | uniq | grep -iv 'geoip' | paste -sd' ')"
_stream_module_args="$(./auto/configure --help | grep -i '\--with-stream' | awk '{print $1}' | sed 's/^[ ]*//g' | sed 's/[ ]*$//g' | grep -v '=' | sort -u | uniq | grep -iv 'geoip' | paste -sd' ')"
sleep 2

bash /opt/gcc/set-static-libstdcxx

./auto/configure \
--build=x86_64-linux-gnu \
--prefix=/usr/share/nginx \
--sbin-path=/usr/sbin/nginx \
--modules-path=/usr/lib64/nginx/modules \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--http-client-body-temp-path=/var/lib/nginx/tmp/client_body \
--http-proxy-temp-path=/var/lib/nginx/tmp/proxy \
--http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi \
--http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi \
--http-scgi-temp-path=/var/lib/nginx/tmp/scgi \
--pid-path=/run/nginx.pid \
--lock-path=/run/lock/subsys/nginx \
--user=nginx \
--group=nginx \
${_http_module_args} \
${_stream_module_args} \
--with-mail \
--with-mail_ssl_module \
--with-file-aio \
--with-poll_module \
--with-select_module \
--with-threads \
--with-pcre-jit \
--with-pcre=../pcre2 \
--with-zlib=../zlib \
--with-openssl=../openssl \
--add-module=../modules/ngx_http_brotli_module \
--add-module=../modules/ngx_http_cache_purge_module \
--add-module=../modules/ngx_http_echo_module \
--add-module=../modules/ngx_http_geoip2_module \
--add-module=../modules/ngx_http_headers_more_filter_module \
--add-module=../modules/ngx_http_memc_module \
--add-module=../modules/ngx_http_redis2_module \
--add-module=../modules/ngx_http_substitutions_filter_module \
--add-module=../modules/ngx_rtmp_module \
--with-ld-opt="$LDFLAGS"

#--with-cc-opt=''
#--with-ld-opt='-Wl,-z,relro -Wl,-z,now'
#--add-module=../modules/ngx_http_naxsi_module/naxsi_src \
#--add-module=../modules/ngx_pagespeed \

make -j2

rm -fr /tmp/nginx
sleep 1
install -m 0755 -d /tmp/nginx
install -m 0755 -d /tmp/nginx/etc/nginx/geoip
install -m 0755 -d /tmp/nginx/usr/lib64/nginx/private
sleep 2
make install DESTDIR=/tmp/nginx
install -v -m 0644 ../geoip2/*.mmdb /tmp/nginx/etc/nginx/geoip/
cp -a /usr/lib64/libmaxminddb.so* /tmp/nginx/usr/lib64/nginx/private/
cp -a /usr/lib64/libbrotli*.so* /tmp/nginx/usr/lib64/nginx/private/

install -m 0755 -d /tmp/nginx/var/www/html
install -m 0755 -d /tmp/nginx/var/lib/nginx/tmp
install -m 0755 -d /tmp/nginx/usr/lib64/nginx/modules
install -m 0755 -d /tmp/nginx/usr/lib/systemd/system
install -m 0755 -d /tmp/nginx/etc/sysconfig
install -m 0755 -d /tmp/nginx/etc/systemd/system/nginx.service.d
install -m 0755 -d /tmp/nginx/etc/logrotate.d
cp -fr /tmp/nginx/usr/local/* /tmp/nginx/usr/
sleep 2
rm -fr /tmp/nginx/usr/local
install -m 0755 -d /tmp/nginx/etc/nginx/conf.d
install -m 0700 -d /tmp/nginx/var/log/nginx
chown -R nginx:nginx /tmp/nginx/var/www/html
chown -R nginx:nginx /tmp/nginx/var/lib/nginx

bash /opt/gcc/set-shared-libstdcxx
############################################################################

echo '[Unit]
Description=nginx - high performance web server
Documentation=https://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
# Nginx will fail to start if /run/nginx.pid already exists but has the wrong
# SELinux context. This might happen when running `nginx -t` from the cmdline.
ExecStartPre=/bin/rm -f /run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecStartPost=/bin/sleep 0.1
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID
KillSignal=SIGQUIT
TimeoutStopSec=5
KillMode=mixed
PrivateTmp=true

[Install]
WantedBy=multi-user.target' > /tmp/nginx/usr/lib/systemd/system/nginx.service
############################################################################

echo '# Configuration file for the nginx service.

NGINX=/usr/sbin/nginx
CONFFILE=/etc/nginx/nginx.conf' > /tmp/nginx/etc/sysconfig/nginx
############################################################################

printf '\x2F\x76\x61\x72\x2F\x6C\x6F\x67\x2F\x6E\x67\x69\x6E\x78\x2F\x2A\x6C\x6F\x67\x20\x7B\x0A\x20\x20\x20\x20\x63\x72\x65\x61\x74\x65\x20\x30\x36\x34\x34\x20\x72\x6F\x6F\x74\x20\x72\x6F\x6F\x74\x0A\x20\x20\x20\x20\x64\x61\x69\x6C\x79\x0A\x20\x20\x20\x20\x72\x6F\x74\x61\x74\x65\x20\x35\x32\x0A\x20\x20\x20\x20\x6D\x69\x73\x73\x69\x6E\x67\x6F\x6B\x0A\x20\x20\x20\x20\x6E\x6F\x74\x69\x66\x65\x6D\x70\x74\x79\x0A\x20\x20\x20\x20\x63\x6F\x6D\x70\x72\x65\x73\x73\x0A\x20\x20\x20\x20\x73\x68\x61\x72\x65\x64\x73\x63\x72\x69\x70\x74\x73\x0A\x20\x20\x20\x20\x70\x6F\x73\x74\x72\x6F\x74\x61\x74\x65\x0A\x20\x20\x20\x20\x20\x20\x20\x20\x2F\x62\x69\x6E\x2F\x6B\x69\x6C\x6C\x20\x2D\x55\x53\x52\x31\x20\x60\x63\x61\x74\x20\x2F\x72\x75\x6E\x2F\x6E\x67\x69\x6E\x78\x2E\x70\x69\x64\x20\x32\x3E\x2F\x64\x65\x76\x2F\x6E\x75\x6C\x6C\x60\x20\x32\x3E\x2F\x64\x65\x76\x2F\x6E\x75\x6C\x6C\x20\x7C\x7C\x20\x74\x72\x75\x65\x0A\x20\x20\x20\x20\x65\x6E\x64\x73\x63\x72\x69\x70\x74\x0A\x20\x20\x20\x20\x70\x6F\x73\x74\x72\x6F\x74\x61\x74\x65\x0A\x20\x20\x20\x20\x20\x20\x20\x20\x2F\x75\x73\x72\x2F\x73\x62\x69\x6E\x2F\x6E\x67\x69\x6E\x78\x20\x2D\x73\x20\x72\x65\x6C\x6F\x61\x64\x20\x3E\x2F\x64\x65\x76\x2F\x6E\x75\x6C\x6C\x20\x32\x3E\x26\x31\x20\x7C\x7C\x20\x74\x72\x75\x65\x0A\x20\x20\x20\x20\x65\x6E\x64\x73\x63\x72\x69\x70\x74\x0A\x7D\x0A\x0A' | dd seek=$((0x0)) conv=notrunc bs=1 of=/tmp/nginx/etc/logrotate.d/nginx
chmod 0644 /tmp/nginx/etc/logrotate.d/nginx

############################################################################

# have added
# ExecStartPost=/bin/sleep 0.1
# to
# /tmp/nginx/usr/lib/systemd/system/nginx.service
# no need this file
# so comment out

#printf "[Service]\nExecStartPost=/bin/sleep 0.1\n" > /tmp/nginx/etc/systemd/system/nginx.service.d/override.conf

############################################################################

echo '#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
TZ='UTC'; export TZ

#yum makecache fast && yum install -y glibc libxml2 libxslt gd perl-libs perl

getent group nginx >/dev/null || groupadd -r nginx
getent passwd nginx >/dev/null || useradd -r -d /var/lib/nginx -g nginx -s /usr/sbin/nologin -c "Nginx web server" nginx
sleep 1
[[ -d /var/www/html ]] || install -m 0755 -d /var/www/html
[[ -d /var/lib/nginx ]] || install -m 0755 -d /var/lib/nginx
chown -R nginx:nginx /var/www/html
chown -R nginx:nginx /var/lib/nginx
systemctl daemon-reload >/dev/null 2>&1
sleep 1
systemctl enable nginx.service 2>/dev/null
exit
' > /tmp/nginx/etc/nginx/.postinstall.txt

sed 's/nginx\/$nginx_version/gws/g' -i /tmp/nginx/etc/nginx/fastcgi.conf
sed 's/nginx\/$nginx_version/gws/g' -i /tmp/nginx/etc/nginx/fastcgi_params

sed 's/nginx\/$nginx_version/gws/g' -i /tmp/nginx/etc/nginx/fastcgi.conf.default
sed 's/nginx\/$nginx_version/gws/g' -i /tmp/nginx/etc/nginx/fastcgi_params.default

sed 's@#user .* nobody;@user  nginx;@g' -i /tmp/nginx/etc/nginx/nginx.conf
sed 's@#user .* nobody;@user  nginx;@g' -i /tmp/nginx/etc/nginx/nginx.conf.default

sed 's@#pid .*nginx.pid;@pid  /run/nginx.pid;@g' -i /tmp/nginx/etc/nginx/nginx.conf
sed 's@#pid .*nginx.pid;@pid  /run/nginx.pid;@g' -i /tmp/nginx/etc/nginx/nginx.conf.default

sed '/ root .* html;/s@html;@/var/www/html;@g' -i /tmp/nginx/etc/nginx/nginx.conf
sed '/ root .* html;/s@html;@/var/www/html;@g' -i /tmp/nginx/etc/nginx/nginx.conf.default

sleep 2
rm -fr /tmp/nginx/etc/nginx/nginx.conf

cd /tmp/nginx
find /tmp/nginx -type f -name .packlist -exec rm -vf '{}' \;
find /tmp/nginx -type f -name perllocal.pod -exec rm -vf '{}' \;
find /tmp/nginx -type f -empty -exec rm -vf '{}' \;
find /tmp/nginx -type f -iname '*.so' -exec chmod -v 0755 '{}' \;
strip usr/sbin/nginx
find usr/lib64/ -type f -iname '*.so*' -exec file '{}' \; | \
  sed -n -e 's/^\(.*\):[  ]*ELF.*, not stripped.*/\1/p' | \
  xargs -I '{}' /usr/bin/strip '{}'
rm -fr run
rm -fr var/run
[ -d usr/man ] && mv -f usr/man usr/share/

echo
sleep 2
tar -Jcvf /tmp/gws-v"${_vmajor}.${_vminor}.${_vpatch}"-1.el7.x86_64.tar.xz *
echo
sleep 2

cd /tmp
rm -fr "${_tmp_dir}"
rm -fr /tmp/nginx
printf '\033[01;32m%s\033[m\n' '  build nginx done'
echo
exit

