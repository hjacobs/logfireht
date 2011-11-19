#!/usr/bin/python

import collections
import re
import traceback

LogEntry = collections.namedtuple('LogEntry', 'ts fid i vhost remote_addr duration method path status_code referrer user_agent response_size session_id')

MONTHS = {
    'Jan': '01',
    'Feb': '02',
    'Mar': '03',
    'Apr': '04',
    'May': '05',
    'Jun': '06',
    'Jul': '07',
    'Aug': '08',
    'Sep': '09',
    'Oct': '10',
    'Nov': '11',
    'Dec': '12',
}

DELIM = re.compile(r'(?<![\\])"')

class RecoverableParseError(Exception):
    pass

class AccessLogParser(object):
    """parse apache access log with the following format:

    LogFormat "%V:%p %a %l %u %t %T %D \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %{X-Forwarded-Protocol}i \"%{Location}o\" %{JSESSIONID}C"
    (see http://httpd.apache.org/docs/2.0/mod/mod_log_config.html)
    """
    def __init__(self):
        pass

    def auto_configure(self, fd):
        """try to auto-configure the parser"""
        pass

    def read(self, fid, fd):
        """read apache access log file"""

        last = ''
        i = 0
        while True:
            line = fd.readline()
            if not line:
                # at end of stream 
                break
            if line.startswith('\x00'):
                # I noticed sporadic null bytes when reading a log file over NFS
                # => LogReader should retry (after sleeping one second)
                raise RecoverableParseError()
            if not line.endswith('\n'):
                last += line
                continue
            line = last + line
            last = ''
            cols = line.split(' ', 8)
            try:
                vhost = cols[0].replace(':80', '')
                remote_addr = cols[1]
                ts = cols[4][1:]
                ts = '%s-%s-%s %s' % (ts[7:11], MONTHS[ts[3:6]], ts[:2], ts[12:])
                duration = int(cols[7])
                last_cols = DELIM.split(cols[8][1:-1])
                status_line = last_cols[0].split(' ')
                method = status_line[0]
                path = status_line[1]
                status_code, response_size = last_cols[1][1:-1].split(' ', 1)
                status_code = int(status_code)
                response_size = 0 if response_size == '-' else int(response_size)
                referrer = last_cols[2]
                user_agent = last_cols[4]
                session_id = last_cols[-1].strip()
                yield LogEntry(fid=fid, ts=ts, i=i, vhost=vhost, remote_addr=remote_addr, duration=duration, method=method, path=path, status_code=status_code, referrer=referrer, user_agent=user_agent, response_size=response_size, session_id=session_id)
            except Exception:
                print 'ERROR parsing line from %d:' % fid, repr(line)
                traceback.print_exc()
            i += 1



if __name__ == '__main__':
    import StringIO

    fd = StringIO.StringIO('www.example.org:80 91.196.112.15 - - [17/Nov/2011:06:25:21 +0100] 0 9465 "GET /category/?q=test HTTP/1.1" 302 - "http://www.example.de/" "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.120 Safari/535.2" - "http://www.example.org/redirect-target/" B0F6A3D05CAEC03D29A2\n'
        + 'www.bla.de')
    parser = AccessLogParser()
    for entry in parser.read(0, fd):
        print entry


