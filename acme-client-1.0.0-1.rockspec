package = 'acme-client'
version = '1.0.0-1'
source  = {
    url    = 'git+https://github.com/a1div0/acme-client.git';
    branch = 'main';
    tag = '1.0.0'
}
description = {
    summary  = "Lua module ACME(v2)-client for Tarantool";
    homepage = 'https://github.com/a1div0/acme-client';
    maintainer = "Alexander Klenov <a.a.klenov@ya.ru>";
    license  = 'BSD2';
}
dependencies = {
    'lua >= 5.1';
}
build = {
    type = 'builtin';
    modules = {
        ['acme-client'] = 'acme-client/init.lua';
    }
}
