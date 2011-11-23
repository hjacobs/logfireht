
$.esc = function(html) {
    if (typeof html != 'string') {
        return html;
    }
    return html.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
};

function getFlag(cc) {
    if (cc == '') {
        return '';
    }
    if (cc == 'uk') {
        cc = 'gb';
    }
    var cu = cc.toUpperCase();
    var name = COUNTRY_NAMES[cu];
    if (typeof name == 'undefined') {
        return '';
    }
    return '<img src="/static/img/flags/' + cc.toLowerCase() + '.png" alt="' + cu + '" title="' + name + '"/>';
}

function truncate(s, l) {
    if (s.length > l) {
        return '<span title="' + $.esc(s) + '">' + $.esc(s.substring(0, l)) + '...</span>';
    }
    return $.esc(s);
}

function insertFlags() {
    $('td.flag').each(function() {
        $(this).html(getFlag($(this).attr('title')));
    });
}

function isIpInNetwork(ip, net) {
    var parts = ip.split('.');
    var iplong = parseInt(parts[0]) << 24 | parseInt(parts[1]) << 16 | parseInt(parts[2]) << 8 | parseInt(parts[3]);
    var netbits = net.split('/');
    parts = netbits[0].split('.');
    var network = parseInt(parts[0]) << 24 | parseInt(parts[1]) << 16 | parseInt(parts[2]) << 8 | parseInt(parts[3]);
    var mask = 0;
    for (var i = 32 - parseInt(netbits[1]); i < 32; i++) {
        mask = mask | (1 << i);
    }

    return (iplong & mask) == (network & mask);
}

function prepareBlacklist(list) {
    var nl = {};
    $.each(list, function(k, v) {
        if (k.substring(0, 8) == 'network:') {
            var parts = k.substring(8).split('.');
            if (!nl['_net:' + parts[0]]) {
                nl['_net:' + parts[0]] = [];
            }
            nl['_net:' + parts[0]].push([k.substring(8), v]);
        } else {
            nl[k] = v;
        }
    });
    return nl;
}

function getBlacklistEntry(list, ip) {
    var entry = list['host:' + ip];
    if (entry) {
        return entry;
    }
    var parts = ip.split('.');
    var entries = list['_net:' + parts[0]];
    if (!entries) {
        return null;
    }
    for (var i=0; i<entries.length; i++) {
        if (isIpInNetwork(ip, entries[i][0])) {
            return entries[i][1];
        }
    }
    return null;
}
