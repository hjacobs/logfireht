#!/usr/bin/python

import collections
import cherrypy
import datetime
import itertools
import json
import logging
import os
import re
import signal
import sys
import time
import lib.jinjatool
from lib.parser import AccessLogParser, RecoverableParseError

from threading import Thread
from optparse import OptionParser


expose = cherrypy.expose
jinja = cherrypy.tools.jinja

class GeoIPWrapper(object):
    def __init__(self, inner):
        self.inner = inner
    def country_code_by_addr(self, ip, default=''):
        if self.inner:
            try:
                return self.inner.country_code_by_addr(ip) or default
            except:
                logging.exception('Failed to get country code for IP %s' % ip)
        return default;

geoip = GeoIPWrapper(None)

REGEX_GROUP_PATTERN = re.compile('\(\?P<(\w*)>[^)]*\)')

# this IP regex is not strict, it's just used for a quick sanity test!
IP_PATTERN = re.compile('^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^[0-9a-f:]+:[0-9a-f:]+$')

def is_ip(ip):
    return ip and IP_PATTERN.match(ip)

class Root(object):
    _cp_config = {
        'tools.staticdir.root': os.path.dirname(os.path.abspath(__file__)),
        'tools.staticfile.root': os.path.dirname(os.path.abspath(__file__))
    }

    def __init__(self, options, aggregator):
        self.options = options
        self.aggregator = aggregator

    def _success(self, msg):
        cherrypy.session['flash_message'] = {'type': 'success', 'message': msg}

    def _error(self, msg):
        cherrypy.session['flash_message'] = {'type': 'error', 'message': msg}

    def _add_flash_msg(self, d):
        flash_msg = cherrypy.session.get('flash_message')
        if flash_msg:
            cherrypy.session['flash_message'] = None
        d['flash_message'] = flash_msg
        return d

    @expose
    @jinja(tpl='index.html')
    def index(self):
        ip_blacklist = self._read_ip_blacklist()
        ip_whitelist = self._read_ip_whitelist()
        return {
            'file_names': self.aggregator.file_names,
            'internal_ips': self.options.internal_ips,
            'internal_urls': self.options.internal_urls,
            'internal_user_agents': self.options.internal_user_agents,
            'ip_blacklist': dict([ (k[0] + ':' + k[1], v) for k, v in ip_blacklist.items() ]),
            'ip_whitelist': dict([ (k[0] + ':' + k[1], v) for k, v in ip_whitelist.items() ]),
        }

    @expose
    def poll(self):
        return json.dumps(self.aggregator.get_statistics(), separators=(',', ':'))

    @expose
    def history_entry(self, ts, field=None, value=None):
        entry = self.aggregator.get_history_entry(int(ts))
        if not entry:
            return json.dumps(None)
        log_entries = collections.deque(maxlen=100)
        ip_countries = {}
        for l in entry.tail:
            if l.matches(field, value):
                log_entries.append(l)
                ip_countries[l.remote_addr] = None
        gi = geoip
        for ip in ip_countries.keys():
            ip_countries[ip] = gi.country_code_by_addr(ip)
        return json.dumps({'log_entries': list(log_entries), 'statistics': entry.statistics, 'remote_addr_countries': ip_countries}, separators=(',', ':'))

    def _read_ip_blacklist(self):
        fpath = self.options.ip_blacklist['path']
        pattern = re.compile(self.options.ip_blacklist['format'])
        entries = {}
        try:
            with open(fpath, 'rb') as fd:
                for line in fd:
                    if line.strip():
                        m = pattern.match(line.strip())
                        entries[(m.group('type'), m.group('address'))] = m.group('comment')
        except IOError:
            logging.exception('Failed to read IP blacklist' + fpath)
        return entries

    def _write_ip_blacklist(self, entries):
        fpath = self.options.ip_blacklist['path']
        write_pattern = self.options.ip_blacklist['format'].replace('\s+', ' ').replace('\s*', ' ')
        entry_template = REGEX_GROUP_PATTERN.sub('##\\1##', write_pattern) + '\n'
        lines = []
        for key, comment in sorted(entries.items()):
            t, address = key
            lines.append(entry_template.replace('##type##', t).replace('##address##', address).replace('##comment##', comment))
        with open(fpath, 'wb') as fd:
            fd.writelines(lines)

    def _read_ip_whitelist(self):
        fpath = self.options.ip_whitelist['path']
        pattern = re.compile(self.options.ip_whitelist['format'])
        entries = {}
        try:
            with open(fpath, 'rb') as fd:
                for line in fd:
                    if line.strip():
                        m = pattern.match(line.strip())
                        entries[(m.group('type'), m.group('address'))] = m.group('comment')
        except IOError:
            logging.exception('Failed to read IP whitelist: ' + fpath)
        return entries

    def _write_ip_whitelist(self, entries):
        fpath = self.options.ip_whitelist['path']
        write_pattern = self.options.ip_whitelist['format'].replace('\s+', ' ').replace('\s*', ' ')
        entry_template = REGEX_GROUP_PATTERN.sub('##\\1##', write_pattern) + '\n'
        lines = []
        for key, comment in sorted(entries.items()):
            t, address = key
            lines.append(entry_template.replace('##type##', t).replace('##address##', address).replace('##comment##', comment))
        with open(fpath, 'wb') as fd:
            fd.writelines(lines)

    @expose
    @jinja(tpl='blacklists.html')
    def blacklists(self):
        ip_blacklist = self._read_ip_blacklist()
        ip_whitelist = self._read_ip_whitelist()
        gi = geoip
        ip_countries = {}
        for t, ip in itertools.chain(ip_blacklist.keys(), ip_whitelist.keys()):
            if t == 'host':
                ip_countries[ip] = gi.country_code_by_addr(ip)
        return self._add_flash_msg({
            'ip_blacklist': ip_blacklist,
            'ip_whitelist': ip_whitelist,
            'ip_countries': ip_countries
        })

    def _escape_comment(self, comment):
        """make sure our black/whitelist comment is safe for most blocking tool formats:
        Use ASCII only and avoid doublequotes.
        """
        return comment.encode('ascii', errors='replace').replace('"', '\'')

    @expose
    def blacklist_ip(self, ip=None, comment=None):
        if not is_ip(ip) or not comment:
            self._error('Invalid IP/comment')
            raise cherrypy.HTTPRedirect(cherrypy.url('/blacklists'))
        entries = self._read_ip_blacklist()
        if ('host', ip) in entries:
            self._success('IP %s was already blacklisted' % (ip,))
            raise cherrypy.HTTPRedirect(cherrypy.url('/blacklists'))

        now = datetime.datetime.now()
        country = geoip.country_code_by_addr(ip, 'unknown')
        # we will encode the comment as ASCII and ignore all non-ascii chars (to make sure the blacklist is read by whatever blocking tool is used)
        entries[('host', ip)] = '%s (country: %s, time: %s)' % (self._escape_comment(comment), country, now.strftime('%Y-%m-%d %H:%M'))
        self._write_ip_blacklist(entries)
        self._success('IP %s has been blacklisted' % (ip,))
        raise cherrypy.HTTPRedirect(cherrypy.url('/blacklists'))

    @expose
    def whitelist_ip(self, ip=None, comment=None):
        if not is_ip(ip) or not comment:
            self._error('Invalid IP/comment')
            raise cherrypy.HTTPRedirect(cherrypy.url('/blacklists'))
        entries = self._read_ip_whitelist()
        if ('host', ip) in entries:
            self._success('IP %s was already whitelisted' % (ip,))
            raise cherrypy.HTTPRedirect(cherrypy.url('/blacklists'))

        now = datetime.datetime.now()
        country = geoip.country_code_by_addr(ip, 'unknown')
        # we will encode the comment as ASCII and ignore all non-ascii chars (to make sure the whitelist is read by whatever blocking tool is used)
        entries[('host', ip)] = '%s (country: %s, time: %s)' % (self._escape_comment(comment), country, now.strftime('%Y-%m-%d %H:%M'))
        self._write_ip_whitelist(entries)
        self._success('IP %s has been whitelisted' % (ip,))
        raise cherrypy.HTTPRedirect(cherrypy.url('/blacklists'))

    @expose
    def blacklist_remove_ip(self, ip=None):
        if not is_ip(ip):
            self._error('Invalid IP')
        entries = self._read_ip_blacklist()
        if ('host', ip) not in entries:
            self._error('IP %s was not found on the blacklist' % (ip,))
            raise cherrypy.HTTPRedirect(cherrypy.url('/blacklists'))
        del entries[('host', ip)]
        self._write_ip_blacklist(entries)
        self._success('IP %s has been removed from the blacklist' % (ip,))
        raise cherrypy.HTTPRedirect(cherrypy.url('/blacklists'))

    @expose
    def whitelist_remove_ip(self, ip=None):
        if not is_ip(ip):
            self._error('Invalid IP')
        entries = self._read_ip_whitelist()
        if ('host', ip) not in entries:
            self._error('IP %s was not found on the whitelist' % (ip,))
            raise cherrypy.HTTPRedirect(cherrypy.url('/blacklists'))
        del entries[('host', ip)]
        self._write_ip_whitelist(entries)
        self._success('IP %s has been removed from the whitelist' % (ip,))
        raise cherrypy.HTTPRedirect(cherrypy.url('/blacklists'))


HistoryEntry = collections.namedtuple('HistoryEntry', 'ts tail statistics')


DEFAULT_TAIL_SIZE = 10000


def parse_timestamp(ts):
    """takes a timestamp such as 2011-09-18 16:00:01,123"""
    if len(ts) < 19:
        ts += ':00'
    struct = time.strptime(ts[:19], '%Y-%m-%d %H:%M:%S')
    return time.mktime(struct)


class LogReader(Thread):
    def __init__(self, fid, fname, parser, receiver, tail=False, follow=False, filterdef=None, tail_size=DEFAULT_TAIL_SIZE):
        Thread.__init__(self, name='LogReader-%d' % (fid,))
        self.fid = fid
        self.fname = fname
        self.parser = parser
        self.receiver = receiver
        self.tail = tail
        self.tail_size = tail_size
        self.follow = follow
        self.filterdef = filterdef or LogFilter()

    def _seek_tail(self, fd, n):
        """seek to start of "tail" (last n lines)"""
        l = os.path.getsize(self.fname)
        s = -1024 * n
        if s * -1 >= l:
            # apparently the file is too small
            # => seek to start of file
            fd.seek(0)
            return
        fd.seek(s, 2)
        contents = fd.read()
        e = len(contents)
        i = 0
        while e >= 0:
            e = contents.rfind('\n', 0, e)
            if e >= 0:
                i += 1
                if i > n:
                    fd.seek(s + e + 1, 2)
                    break

    def _seek_time(self, fd, ts):
        """try to seek to our start time"""
        s = os.path.getsize(self.fname)
        fd.seek(0)

        if s < 8192:
            # file is too small => we do not need to seek around
            return

        file_start = None
        for entry in self.parser.read(0, fd):
            file_start = entry.ts
            break

        fd.seek(-1024, 2)
        file_end = None
        for entry in self.parser.read(0, fd):
            file_end = entry.ts
            break

        if not file_start or not file_end:
            fd.seek(0)
            return

        start = parse_timestamp(file_start)
        t = parse_timestamp(ts)
        end = parse_timestamp(file_end)

        if end - start <= 0:
            fd.seek(0)
            return

        ratio = max(0, (t - start) / (end - start) - 0.2)
        fd.seek(s * ratio)

    def run(self):
        fid = self.fid
        receiver = self.receiver
        filt = self.filterdef
        waits = 0
        fd = open(self.fname, 'rb')
        try:
            self.parser.auto_configure(fd)
            if self.tail:
                self._seek_tail(fd, self.tail_size)
            elif filt.time_from:
                self._seek_time(fd, filt.time_from)
            while True:
                where = fd.tell()
                try:
                    for entry in self.parser.read(fid, fd):
                        where = fd.tell()
                        if filt.matches(entry):
                            receiver.add(entry)
                except RecoverableParseError:
                    print 'RecoverableParseError', fid, where
                    time.sleep(1.0)
                    fd.close()
                    fd = open(self.fname, 'rb')
                    fd.seek(where)
                    continue
                if not self.follow:
                    receiver.eof(fid)
                    break
                time.sleep(1.0)
                waits += 1
                if waits > 4:
                    # no new lines for 5 seconds: re-open log file
                    # (could be logrotate)
                    fd.close()
                    fd = open(self.fname, 'rb')
                    waits = 0
        finally:
            fd.close()


class Watcher:
    """this class solves two problems with multithreaded
    programs in Python, (1) a signal might be delivered
    to any thread (which is just a malfeature) and (2) if
    the thread that gets the signal is waiting, the signal
    is ignored (which is a bug).

    The watcher is a concurrent process (not thread) that
    waits for a signal and the process that contains the
    threads.  See Appendix A of The Little Book of Semaphores.
    http://greenteapress.com/semaphores/

    I have only tested this on Linux.  I would expect it to
    work on the Macintosh and not work on Windows.
    """

    def __init__(self):
        """ Creates a child thread, which returns.  The parent
            thread waits for a KeyboardInterrupt and then kills
            the child thread.
        """
        self.child = os.fork()
        if self.child == 0:
            return
        else:
            self.watch()

    def watch(self):
        try:
            os.wait()
        except KeyboardInterrupt:
            # I put the capital B in KeyBoardInterrupt so I can
            # tell when the Watcher gets the SIGINT
            print '\033[0m' + 'KeyBoardInterrupt'
            self.kill()
        sys.exit()

    def kill(self):
        try:
            os.kill(self.child, signal.SIGKILL)
        except OSError: pass

class LogAggregator(object):
    def __init__(self, file_names, follow=False, tail_size=DEFAULT_TAIL_SIZE):
        self.file_names = file_names
        self.follow = follow
        n = len(file_names)
        self.open_files = set(range(n))
        self.tail = collections.deque(maxlen=tail_size)
        self.history = collections.deque(maxlen=10)

    def add(self, entry):
        if self.tail and self.follow:
            d = datetime.timedelta(seconds=300)
            ago = datetime.datetime.now() - d
            if self.tail[0].ts < ago.isoformat(' '):
                self.tail.popleft()
        self.tail.append(entry)

    def eof(self, fid):
        self.open_files.remove(fid)

    def get_history_entry(self, ts):
        l = list(self.history)
        for e in l:
            if e.ts == ts:
                return e
        return None

    def get_statistics(self):
        now = int(time.time() * 1000)
        if self.follow and self.history and self.history[-1].ts >= now - 1500:
            return self.history[-1].statistics
        tail = list(self.tail)
        gi = geoip
        counts_by_remote_addr = collections.Counter([ entry.remote_addr for entry in tail])
        counts_by_vhost = collections.Counter([ entry.vhost for entry in tail])
        counts_by_path = collections.Counter([ entry.vhost + entry.path for entry in tail])
        counts_by_status_code = collections.Counter([ entry.status_code for entry in tail])
        counts_by_user_agent = collections.Counter([ entry.user_agent for entry in tail])
        counts_by_duration = collections.Counter([ entry.duration/250000 for entry in tail ])
        statistics = {
            'ts': now,
            'tail_start': tail[0].ts if tail else None,
            'tail_end': tail[-1].ts if tail else None,
            'tail_size': len(tail),
            'most_common_remote_addrs': [(ip, gi.country_code_by_addr(ip), count) for ip, count in counts_by_remote_addr.most_common(50) ],
            'most_common_vhosts': counts_by_vhost.most_common(50),
            'most_common_paths': counts_by_path.most_common(50),
            'most_common_status_codes': counts_by_status_code.most_common(50),
            'most_common_user_agents': counts_by_user_agent.most_common(50),
            'most_common_durations': counts_by_duration.most_common(50)
        }
        histentry = HistoryEntry(ts=now, tail=tail, statistics=statistics)
        self.history.append(histentry)
        return statistics

class OutputThread(Thread):
    def __init__(self, aggregator, fd=sys.stdout):
        Thread.__init__(self, name='OutputThread')
        self.aggregator = aggregator
        self.fd = fd

    def write_statistics(self):
        fd = self.fd
        fd.write('-' * 40)
        fd.write('\n')
        stats = self.aggregator.get_statistics()
        fd.write('%s - %s (%d requests)\n' % (stats['tail_start'], stats['tail_end'], stats['tail_size']))
        fd.write('Most common IPs:\n')
        for ip, country_code, count in  stats['most_common_remote_addrs']:
            fd.write(' %2s %15s %5d\n' % (country_code, ip, count))
        fd.write('Most common VHosts:\n')
        for vhost, count in  stats['most_common_vhosts']:
            fd.write(' %70s %5d\n' % (vhost, count))
        fd.write('Most common URLs:\n')
        for url, count in  stats['most_common_paths']:
            fd.write(' %70s %5d\n' % (url[:70], count))

    def run(self):
        while self.aggregator.open_files:
            self.write_statistics()
            time.sleep(0.5)
        self.write_statistics()

class LogFilter(object):
    def __init__(self):
        self.grep = None
        self.time_from = None
        self.time_to = None

    def matches(self, entry):
        ok = True
        if ok and self.grep:
            ok = self.grep in entry.message or self.grep in entry.source_class
        if ok and self.time_from:
            ok = entry.ts >= self.time_from
        if ok and self.time_to:
            ok = entry.ts < self.time_to

        return ok

def load_geoip():
    global geoip
    try:
        import pygeoip
        geoip = GeoIPWrapper(pygeoip.GeoIP('GeoIP.dat', flags=pygeoip.MEMORY_CACHE))
    except ImportError:
        print 'WARNING: pygeoip module not found'
    except IOError:
        print 'WARNING: GeoIP.dat not found'
        geoip = MockGeoIP()

def main():
    Watcher()
    parser = OptionParser(usage='Usage: %prog [OPTION]... [FILE]...')
    parser.add_option('-s', '--server', action='store_true',
                      help='start HTTP server')
    parser.add_option('-f', '--follow', action='store_true', dest='follow',
                      help='keep file open reading new lines (like tail)')
    parser.add_option('-t', '--tail', dest='tail', action='store_true',
                      help='show last N lines (default %d)' % DEFAULT_TAIL_SIZE)
    parser.add_option('-n', '--lines', dest='tail_size', default=DEFAULT_TAIL_SIZE, type='int', metavar='N',
                      help='show last N lines (instead of default %d)' % DEFAULT_TAIL_SIZE)
    parser.add_option('-g', '--grep', dest='grep', metavar='PATTERN',
                      help='only show log entries matching pattern')
    parser.add_option('--time-from', dest='time_from', metavar='DATETIME',
                      help='only show log entries starting at DATETIME')
    parser.add_option('--time-to', dest='time_to', metavar='DATETIME',
                      help='only show log entries until DATETIME')

    (options, args) = parser.parse_args()

    merged_config = {
        'options': {
            'internal_ips': {
                '127.0.0.1': 'Localhost'
            },
            'internal_urls': {},
            'internal_user_agents': {},
            'ip_blacklist': {
                'path': 'ip_blacklist.txt',
                'format': '(?P<type>\w+)\s+(?P<address>[0-9a-f./:]+)\s+(?P<comment>.*)'
            },
            'ip_whitelist': {
                'path': 'ip_whitelist.txt',
                'format': '(?P<type>\w+)\s+(?P<address>[0-9a-f./:]+)\s+(?P<comment>.*)'
            }
        },
        'files': []
    }
    config_file = os.path.expanduser('~/.logfirehtrc')
    if not os.path.isfile(config_file):
        # fallback using global configuration file
        config_file = '/etc/logfirehtrc'
    if os.path.isfile(config_file):
        config = json.load(open(config_file, 'rb'))
        if config.get('options'):
            merged_config['options'].update(config.get('options', {}))
        if config.get('files'):
            merged_config['files'] = config.get('files')

    for key, val in merged_config['options'].items():
        if not getattr(options, key, None):
            setattr(options, key, val)
    if not args:
        args = merged_config['files']

    filterdef = LogFilter()
    filterdef.grep = options.grep
    filterdef.time_from = options.time_from
    filterdef.time_to = options.time_to

    load_geoip()

    used_file_names = set()
    file_names = args
    aggregator = LogAggregator(file_names, follow=options.follow, tail_size=options.tail_size)
    readers = []
    fid = 0
    for fname_with_name in file_names:
        if ':' in fname_with_name:
            name, unused, fpath = fname_with_name.partition(':')
        else:
            fpath = fname_with_name
            name = 'L%02d' % (fid + 1)
        i = 1
        while name in used_file_names:
            name = name + str(i)
            i += 1
        file_names[fid] = name
        used_file_names.add(name)
        parser = AccessLogParser()
        readers.append(LogReader(fid, fpath, parser, aggregator, tail=options.tail, tail_size=options.tail_size/len(file_names), follow=options.follow, filterdef=filterdef))
        fid += 1
    for reader in readers:
        reader.start()

    if options.server:
        conf = os.path.dirname(os.path.abspath(__file__)) + '/site.conf'
        cherrypy.config.update(conf)

        app = cherrypy.tree.mount(Root(options, aggregator), '', conf)
        cherrypy.engine.start()
        cherrypy.engine.block()

    else:
        out = OutputThread(aggregator)
        out.start()


if __name__ == '__main__':
    main()

