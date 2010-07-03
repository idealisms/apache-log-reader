#!/usr/bin/env python

"""Unittests"""

import sys
import unittest
import tempfile
import datetime

try:
  import log_reader
except ImportError:
  print "unable to find log_reader module"
  sys.exit(1)


class ApacheReaderTest(unittest.TestCase):
  def testClassAttributes(self):
    self.assertEquals(log_reader.ApacheReader.COMMON,
                      '%h %l %u %t "%r" %>s %b')
    self.assertEquals(log_reader.ApacheReader.COMBINED,
                      '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"')

  def testUsername(self):
    input = ["test\n", "foo"]
    reader = log_reader.ApacheReader(iter(input), '%u')
    lines = [f for f in reader]
    self.assertEquals(lines[0]['username'], 'test')
    self.assertEquals(lines[1]['username'], 'foo')

  def testIps(self):
    input = ("0.0.0.0\n",
             "1.2.3.4, 5.6.7.8\n",
             'unknown, 255.255.255.255\n',
             '255.0.255.0, unknown\n',
             '100.100.100.100\n',
             '200.169.54.33, unknown, 200.169.63.242')
    reader = log_reader.ApacheReader(iter(input), '%h')

    lines = [f for f in reader]
    self.assertEquals(lines[0]['ips'], ['0.0.0.0'])
    self.assertEquals(lines[1]['ips'], ['1.2.3.4', '5.6.7.8'])
    self.assertEquals(lines[2]['ips'], ['unknown', '255.255.255.255'])
    self.assertEquals(lines[3]['ips'], ['255.0.255.0', 'unknown'])
    self.assertEquals(lines[4]['ips'], ['100.100.100.100'])
    self.assertEquals(lines[5]['ips'],
                      ['200.169.54.33', 'unknown', '200.169.63.242'])

  def testReading(self):
    reader = log_reader.ApacheReader(file('access.log'))
    lines = [f for f in reader]
    reader = None
    reader = log_reader.ApacheReader(file('access.log'))
    for fields in reader:
      pass

  def testEscaping(self):
    input = ('"test test test"\n',
             '"foo"')
    reader = log_reader.ApacheReader(iter(input), '"%u"')
    lines = [f for f in reader]
    self.assertEquals(lines[0]['username'], 'test test test')
    self.assertEquals(lines[1]['username'], 'foo')

  def testDatetime(self):
    input = ("[03/Mar/2005:06:47:18 -0500]\n\n",
             "[03/Jan/2005:00:41:10 -0800]")
    reader = log_reader.ApacheReader(iter(input), '%t')
    lines = [f for f in reader]
    self.assertEquals(lines[0]['time'], datetime.datetime(2005, 3, 3, 6, 47, 18))
    self.assertEquals(lines[1]['time'], datetime.datetime(2005, 1, 3, 0, 41, 10))

  def testRequest(self):
    input = ('"GET /path/to/page.html HTTP/1.0"\n\n',
             '"POST /foo/bar/?betz=10 HTTP/1.0"')
    reader = log_reader.ApacheReader(iter(input), '"%r"')
    lines = [f for f in reader]
    self.assertEquals(lines[0]['method'], 'GET')
    self.assertEquals(lines[0]['protocol'], 'HTTP/1.0')
    self.assertEquals(lines[0]['path'], '/path/to/page.html')
    self.assertEquals(lines[1]['method'], 'POST')
    self.assertEquals(lines[1]['protocol'], 'HTTP/1.0')
    self.assertEquals(lines[1]['path'], '/foo/bar/?betz=10')

  def testSizeAndReferer(self):
    input = ('1234 "test"\n\n',
             '22345 "test test"')
    reader = log_reader.ApacheReader(iter(input), '%b "%{Referer}i"')
    lines = [f for f in reader]
    self.assertEquals(lines[0], {'referer': 'test', 'size': 1234})
    self.assertEquals(lines[1], {'referer': 'test test', 'size': 22345})

  def testRefererUser(self):
    input = ('"test" username\n\n',
             '"test test" foobar')
    reader = log_reader.ApacheReader(iter(input), '"%{Referer}i" %u')
    lines = [f for f in reader]
    self.assertEquals(lines[0], {'referer': 'test', 'username': 'username'})
    self.assertEquals(lines[1], {'referer': 'test test', 'username': 'foobar'})

  def testCurline(self):
    input = ('"test" username\n\n',
             '"test test" foobar')
    reader = log_reader.ApacheReader(iter(input), '"%{Referer}i" %u')
    lines = [reader.curline for f in reader]
    self.assertEquals(lines[0], input[0])
    self.assertEquals(lines[1], input[1])

  def testParseLine(self):
    parse_line = log_reader.ApacheReader.parse_line
    line = ('"1.2.3.4 - - [03/Jul/2007:18:48:56 +1000] "GET /example'
            ' HTTP/1.1" 200 1234 "http://www.example.com/referrer"'
            ' "user-agent/1.0"')
    d = parse_line(line)
    self.assertEquals(d['referer'], 'http://www.example.com/referrer')

  def testDoubleQuotes(self):
    input = ('"noquote" "escape test\\" test"\n',
             '"test" "double ""quote test"')
    reader = log_reader.ApacheReader(iter(input), '"%u" "%{User-Agent}i"')
    lines = [f for f in reader]
    self.assertEquals(lines[0], {'username': 'noquote',
                                 'user-agent': 'escape test" test'})
    self.assertEquals(lines[1], {'username': 'test',
                                 'user-agent': 'double "quote test'})

  def testCustomFormat(self):
    input = ('"test" "test2"\n',
             '"another test" "more spaces"')
    reader = log_reader.ApacheReader(iter(input), '"%{Foo}i" "%{Bar}i"')
    lines = [f for f in reader]
    self.assertEquals(lines[0], {'Foo': 'test', 'Bar': 'test2' })
    self.assertEquals(lines[1], {'Foo': 'another test', 'Bar': 'more spaces'})

if '__main__' == __name__:
  unittest.main()
