
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

function insertFlags() {2
    $('td.flag').each(function() {
        $(this).html(getFlag($(this).attr('title')));
    });
}
