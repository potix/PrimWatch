#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import logging.handlers
import os
import random
import socket
import struct
import traceback
import time
import sys
import errno

from urllib2 import urlopen, HTTPError, URLError
from Queue import Queue
from threading import Thread, Lock
from optparse import OptionParser


class Config(object):
    """Manage configuration."""

    def __init__(self, data=None, root=None):
        self.data = data or {}
        self.root = root

    def __getitem__(self, key):
        return self.get(key)

    def setdefault(self, key, default):
        return self.data.setdefault(key, default)

    def iteritems(self):
        for k, v in self.data.iteritems():
            yield (k, Config(v, self.root))

    def load(self, path):
        if not path or not os.path.exists(path):
            assert 'File "%s" does not exist.' % path
        self.data = json.load(open(path))
        self.root = self.data

    def get(self, key, default=''):
        value = self.data.get(key, default)
        if isinstance(value, dict):
            return Config(value, self.root)
        return value

    def get_bool(self, key, default=''):
        value = self.get(key, default)
        if isinstance(value, basestring):
            try:
                return bool(float(value))
            except ValueError:
                return value.strip().lower() in ('yes', 'true')
        try:
            return bool(value)
        except (TypeError, ValueError):
            return False

    def get_int(self, key, default=''):
        return int(self.get(key, default))

    def root(self):
        return Config(self.root, self.root)

    def is_root(self):
        return self.data is self.root


class Context(object):
    def __init__(self, config, logger, address, default_timeout, default_retry):
        self.config = config
        self.logger = logger
        self.address = address
        self.default_timeout = default_timeout
        self.default_retry = default_retry


class Interface():
    """Interface object."""


class HealthCheck(Interface):
    __registry__ = []
    log = None

    @classmethod
    def get_components(cls):
        return set(cls.__registry__)

    @classmethod
    def get_types(cls):
        """Return list of watch types."""
        types = set([t for t, c in cls.__registry__])
        return list(types)

    def __init__(self):
        self.context = None
        self.config = None
        self.log = None
        self.address = None

    def init(self, context):
        self.context = context
        self.config = context.config
        self.log = context.logger
        self.address = context.address

    def is_alive(self):
        """If server is alive, return True. Otherwise return False."""
        raise NotImplementedError()


def get_watch_types():
    return HealthCheck.get_types()


def get_components():
    return HealthCheck.get_components()


def provider(watch_type):
    """class decorator for activate implemented HealthCheck classes."""

    def __provider(cls):
        HealthCheck.__registry__.append((watch_type, cls))
        return cls

    return __provider


@provider('TCP')
class TCPHealthCheck(HealthCheck):
    """Health check with TCP.

Configuration attributes:
  port    : TCP port number.
  timeout : A timeout on socket operations.
            This value can be a float, giving in seconds.
  retry   : A number of retry operation.

Example:
  "TCP": {
    "port": 5000,
    "timeout": 5,
    "retry": 3
  }"""

    def is_alive(self):
        port = self.config.get_int('port')
        timeout = self.config.get_int('timeout', self.context.default_timeout)
        retry = self.config.get_int('retry', self.context.default_retry)
        for i in range(retry):
            if self.connect(port, timeout):
                return True
            self.log.debug('Retry TCP health check: %d', i + 1)
        return False

    def connect(self, port, timeout):
        try:
            start = time.time()
            host = socket.gethostbyname(self.address)
            try:
                port = int(self.port)
            except ValueError:
                port = socket.getservbyname(port)
            sock = socket.socket()
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            elapsed = (time.time() - start) * 1000
            self.log.debug('Successfully to connect %s:%s. time: %lf ms', self.address, port, elapsed)
            return True
        except Exception as e:
            self.log.info('Failed to connect TCP %s:%s.', self.address, port)
        return False


@provider('ICMP')
class ICMPHealthCheck(HealthCheck):
    """Health check with ICMP.

Configuration attributes:
  timeout : A timeout on socket operations.
            This value can be a float, giving in seconds.
  retry   : A number of retry operation.

Example:
  "ICMP": {
    "timeout": 3
    "retry": 5
  }"""
    ECHO_REPLY = 0
    ECHO_REQUEST = 8

    def is_alive(self):
        timeout = self.config.get_int('timeout', self.context.default_timeout)
        retry = self.config.get_int('retry', self.context.default_retry)
        sid = (int(time.time() * 1000) + os.getpid() + random.randint(0, 0xffff)) & 0xffff
        seq = 1
        for i in range(retry):
            if self.send(sid, seq, timeout):
                return True
            self.log.debug('Retry ICMP health check: %d', i + 1)
        return False

    def get_checksum(self, source):
        checksum = 0
        max_count = len(source)
        count = 0
        while max_count - count > 1:
            val = (ord(source[count + 1]) << 8) | ord(source[count])
            checksum += val
            count += 2
        if max_count - count == 1:
            checksum += ord(source[count])
        checksum &= 0xffffffff
        checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = ~checksum & 0xffff
        checksum = socket.htons(checksum)
        return checksum

    def send(self, sid, seq, timeout):
        r_packet = None
        try:
            start = time.time()
            host = self.address
            protocol = socket.IPPROTO_ICMP
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
            sock.settimeout(timeout)
            send_header = struct.pack('!bbHHH', self.ECHO_REQUEST, 0, 0, sid, seq)
            double_size = struct.calcsize('d')
            send_data = struct.pack('d', time.time()) + 'Are you alive?'
            checksum = self.get_checksum(send_header + send_data)
            send_header = struct.pack('!bbHHH', self.ECHO_REQUEST, 0, checksum, sid, seq)
            send_packet = send_header + send_data
            sock.sendto(send_packet, (host, protocol))

            while True:
                r_packet, from_host = sock.recvfrom(1024)
                r_header = r_packet[20:28]
                r_type, r_code, r_checksum, r_id, r_seq = struct.unpack('!bbHHH', str(r_header))
                if self.ECHO_REPLY == r_type and sid == r_id and seq == r_seq:
                    break
            sock.close()
            ttl = (time.time() - struct.unpack('d', str(r_packet[28:28 + double_size]))[0]) * 1000
            elapsed = (time.time() - start) * 1000
            self.log.debug('ICMP sent %s. id: %d, ttl: %lf ms, time: %lf ms' % (self.address, sid, ttl, elapsed))
            return True

        except Exception as e:
            self.log.info('Failed to send ICMP %s, %s', self.address, e)
        return False


@provider('URL')
class HTTPHealthCheck(HealthCheck):
    """Health check for URL.

Configuration attributes:
  url     : The target URL for health check.
  codes   : List of expected HTTP response code.
  timeout : A timeout on socket operations.
            This value can be a float, giving in seconds.
  retry   : A number of retry operation.

Example:
  "URL": {
    "url": "http://example.com/path/"
    "codes": [200, 201, ...],
    "timeout": 3,
    "retry": 5
  }"""

    def is_alive(self):
        timeout = self.config.get_int('timeout', self.context.default_timeout)
        retry = self.config.get('retry', self.context.default_retry)
        expect_codes = self.config.get('codes', [200])
        url = self.config.get('url')
        for i in range(retry):
            if self.send(url, timeout) in expect_codes:
                return True
            self.log.debug('Retry HTTP[S] health check: %d', i + 1)
        return False

    def send(self, url, timeout):
        code = -1
        try:
            start = time.time()
            r = urlopen(url, timeout=timeout)
            elapsed = (time.time() - start) * 1000
            self.log.debug('Sent a http request %s. Response: %s, time: %lf ms', url, r.code, elapsed)
            return r.code
        except HTTPError as e:
            code = e.code
            self.log.warn('Failed to open %s. code: %s', url, code)
            return code
        except URLError as e:
            self.log.warn('Failed to open %s. reason: %s', url, e.reason)
            return code


class HealthCheckTask(object):
    def __init__(self, provider, config, logger, address, default_timeout, default_retry, target):
        self.provider = provider
        self.config = config
        self.logger = logger
        self.context = Context(config, logger, address, default_timeout, default_retry)
        self.alive = False
        self.done = False
        self.watch_target = target

    def init(self):
        self.alive = False
        self.done = False

    def run(self):
        try:
            p = self.provider()
            p.init(self.context)
            self.alive = p.is_alive()
        except:
            pass
        self.done = True

    def is_alive(self):
        return self.alive

    def is_done(self):
        return self.done


class HealthCheckTarget(object):
    def __init__(self, name, config, logger, default_timeout=5, default_retry=3):
        self.name = name
        self.config = config
        self.logger = logger
        self.default_timeout = default_timeout
        self.default_retry = default_retry
        self.address = config.get('address')
        self.force_down = config.get('force_down')
        self.providers = get_components()
        self._tasks = None
        self._start_time = 0

    def init(self):
        self._start_time = time.time()
        if self._tasks:
            for t in self._tasks:
                t.init()

    def get_tasks(self):
        self.init()
        if self._tasks is not None:
            return self._tasks
        self._tasks = []
        for k, v in self.config.get('watches', {}).iteritems():
            matched = False
            for t, p in self.providers:
                if k and k.upper() == t:
                    self._tasks.append(HealthCheckTask(p, v, self.logger, self.address,
                                                       self.default_timeout, self.default_retry, self))
                    matched = True
                    break
            if not matched:
                self.logger.warn('Unknown watch type: %s, target: %s', k, self.name)

        return self._tasks

    def is_alive(self):
        if self.force_down:
            return False
        return False not in [t.is_alive() for t in self._tasks]

    def is_done(self):
        """If all watch tasks finished, return True."""
        if self._tasks is not None:
            return False not in [t.is_done() for t in self._tasks]
        return False


class HealthCheckService(object):
    def __init__(self, config):
        self.config = config
        self.worker_size = config.get('workers', 4)
        self.default_timeout = config.get('default_timeout', 5)
        self.default_retry = config.get('default_retry', 3)
        self.logger = None
        self._targets = []
        self._queue = Queue()
        self._threads = []
        self._lock = Lock()

    def init_logger(self):
    # init logger
        logging = self.config.get('logging', {})
        log_type = logging.get('type', 'syslog')
        log_file = logging.get('file', None)
        log_level = logging.get('level', 'DEBUG')
        try:
            self.logger, handler = logger_handler_factory(log_type, log_file, log_level)
        except:
            traceback.print_exc(file=sys.stderr)
            sys.exit(1)

    def prepare(self):
        self.init_logger()
        for k, v in self.config.get('targets').iteritems():
            target = HealthCheckTarget(k, v, self.logger, self.default_timeout, self.default_retry)
            self._targets.append(target)
        task_cnt = 0
        for target in self._targets:
            for task in target.get_tasks():
                self._queue.put(task)
                task_cnt += 1
        if task_cnt < self.worker_size:
            self.worker_size = task_cnt

    def run(self):
        start = time.time()
        self.logger.info('Start healthcheck')
        for i in range(self.worker_size):
            t = Thread(target=self._worker)
            self._threads.append(t)
            t.start()
        self._queue.join()
        for t in self._threads:
           t.join
        self.logger.info('Done all tasks. elapsed time: %lf sec', (time.time() - start))

    def shutdown(self):
        while not self._queue.empty():
            self._queue.get()
            self._queue.task_done()
        self._queue.join()
        for t in self._threads:
           t.join()

    def _worker(self):
        while not self._queue.empty():
            task = self._queue.get()
            task.run()
            target = task.watch_target
            if target.is_done():
                result = target.is_alive() and 'up' or 'down'
                self.logger.info("%s(%s) is %s", target.name, target.address, result)
                with self._lock:
                  print('%s %s' % (target.address, result))
            self._queue.task_done()


def logger_handler_factory(log_type='syslog', log_file=None, log_level='WARNING', log_id='Main', log_format=None):
    """Return a thread safe logger."""
    logger = logging.getLogger(log_id)
    log_type = log_type.lower()
    if log_type == 'file':
        try:
            os.makedirs(os.path.dirname(log_file))
        except os.error, e:
            if e.errno != errno.EEXIST:
                raise
        handler = logging.handlers.TimedRotatingFileHandler(log_file, "D", 1)
    elif log_type in ('winlog', 'eventlog', 'nteventlog'):
        # win32 extensions
        handler = logging.handlers.NTEventLogHandler(log_id, logtype='Application')
    elif log_type in ('syslog', 'unix'):
        handler = logging.handlers.SysLogHandler('/dev/log')
    elif log_type in ('stderr',):
        handler = logging.StreamHandler(sys.stderr)
    else:
        handler = logging.handlers.BufferingHandler(0)

    if not log_format:
        log_format = 'PrimWatch [%(module)s] %(levelname)s: %(message)s'
        if log_type in ('file', 'stderr'):
            log_format = '%(asctime)s ' + log_format
    datefmt = ''
    if log_type == 'stderr':
        datefmt = '%X'
    log_level = log_level.upper()
    if log_level in ('DEBUG', 'ALL'):
        logger.setLevel(logging.DEBUG)
    elif log_level == 'INFO':
        logger.setLevel(logging.INFO)
    elif log_level == 'ERROR':
        logger.setLevel(logging.ERROR)
    elif log_level == 'CRITICAL':
        logger.setLevel(logging.CRITICAL)
    else:
        logger.setLevel(logging.WARNING)
    formatter = logging.Formatter(log_format, datefmt)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    # Remember our handler so that we can remove it later
    logger._handler = handler
    return logger, handler


def main():
    op = OptionParser()
    op.add_option('-c', '--config', dest='config', default='/etc/primwatch/healthcheck.json',
                  help='set configuration file (default: %default)')
    op.add_option('-l', '--list', action='store_true', dest='show_types',
                  default=False, help='show watch types and exit')
    opts, args = op.parse_args()
    if opts.show_types:
        print('Supported watch types:')
        for k, c in get_components():
            print('%s\n%s' % ('{0:-^72}\n'.format(' %s ' % k), c.__doc__))
        sys.exit(0)
    config = Config()
    if opts.config:
        path = opts.config
        if not os.path.exists(path):
            sys.exit('config file %s does not exist.' % path)
        config.load(path)
    service = HealthCheckService(config)
    service.prepare()
    try:
        service.run()
    except KeyboardInterrupt:
        service.shutdown()
        sys.exit(0)


if __name__ == '__main__':
    main()
