a fast Apache log file reader

ApacheReader is a class for parsing apache httpd log lines
into python dictionaries.  It's implemented as a CPython
module because string processing in python is slow.

Example:

Python 2.4.2 (#2, Sep 30 2005, 21:19:01)
[GCC 4.0.2 20050808 (prerelease) (Ubuntu 4.0.1-4ubuntu8)] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import log_reader
>>> reader = log_reader.ApacheReader(file('access.log'))
>>> reader.next()
{'username': '-', 'status': 200, 'ident': '-', 'tz':
'-0500', 'protocol': 'HTTP/1.0', 'user-agent': 'Mozilla/4.0
(compatible; MSIE 6.0; Windows 98; iTreeSurf 3.6.1 (Build
056))', 'ips': ['123.123.123.123'], 'referer': 'Field blocked
by Outpost (http://www.agnitum.com)', 'time':
datetime.datetime(2005, 3, 3, 21, 37, 58), 'path':
'/webnote/webnote', 'method': 'GET', 'size': 46472}
>>> status = [f['status'] for f in reader]
>>> status.count(200) # request ok
14047
>>> status.count(404) # file not found
159

The class takes either a filename or an iterable object
and optionally a log file format (combined format is default).

Release History
2006.03.06 - initial release (1.0)
http://ponderer.org/download/log_reader-1.0.tar.gz

2006.07.08 - add ApacheReader.parse_line class method
             (patch from Damien Miller)
           - add support for double quote escaped lines
             (patch from Damien Miller)
http://ponderer.org/download/log_reader-1.1.tar.gz

2008.05.30 - parse request path even when protocol is not present
             (patch from Kevin Turner at janrain)
           - handle format string "Host"
             (patch from Kevin Turner at janrain)
           - handle format character %D (elapsed time)
             (patch from Kevin Turner at janrain)
http://ponderer.org/download/log_reader-1.2.tar.gz
