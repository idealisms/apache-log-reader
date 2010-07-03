#!/usr/bin/env python
import gc
import sys
try:
  import log_reader
except ImportError:
  print "unable to find log_reader module"
  sys.exit(1)


line = ('"1.2.3.4 - - [03/Jul/2007:18:48:56 +1000] "GET /example'
        ' HTTP/1.1" 200 1234 "http://www.example.com/referrer"'
        ' "user-agent/1.0"')

for i in xrange(1000000):
  #parse_line = log_reader.ApacheReader.parse_line
  #parse_line(line)
  #continue

  reader = log_reader.ApacheReader('access.log')
  for fields in reader:
    pass
  reader = None
  gc.collect()
  reader = log_reader.ApacheReader(file('access.log'))
  for fields in reader:
    pass
  sys.stdout.write('.');
  sys.stdout.flush()
  reader = None
  gc.collect()
