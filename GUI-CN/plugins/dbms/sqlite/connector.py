#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

try:
    import sqlite3
except:
    pass

import logging

from lib.core.common import getSafeExString
from lib.core.convert import getText
from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapMissingDependence
from plugins.generic.connector import Connector as GenericConnector

import sqlite3

class Connector(GenericConnector):
    """
    Homepage: http://pysqlite.googlecode.com/ and http://packages.ubuntu.com/quantal/python-sqlite
    User guide: http://docs.python.org/release/2.5/lib/module-sqlite3.html
    API: http://docs.python.org/library/sqlite3.html
    Debian package: python-sqlite (SQLite 2), python-pysqlite3 (SQLite 3)
    License: MIT

    Possible connectors: http://wiki.python.org/moin/SQLite
    """

    def __init__(self):
        GenericConnector.__init__(self)
        self.__sqlite = sqlite3

    def connect(self):
        self.initConnection()
        self.checkFileDb()

        try:
            self.connector = self.__sqlite.connect(database=self.db, check_same_thread=False, timeout=conf.timeout)

            cursor = self.connector.cursor()
            cursor.execute("SELECT * FROM sqlite_master")
            cursor.close()

        except (self.__sqlite.DatabaseError, self.__sqlite.OperationalError):
            warnMsg = "无法使用 SQLite 3 库进行连接,尝试使用 SQLite 2"
            logger.warning(warnMsg)

            try:
                try:
                    import sqlite
                except ImportError:
                    errMsg = "sqlmap 需要 'python-sqlite' 第三方库才能直接连接到数据库 '%s'" % self.db
                    raise SqlmapMissingDependence(errMsg)

                self.__sqlite = sqlite
                self.connector = self.__sqlite.connect(database=self.db, check_same_thread=False, timeout=conf.timeout)
            except (self.__sqlite.DatabaseError, self.__sqlite.OperationalError) as ex:
                raise SqlmapConnectionException(getSafeExString(ex))

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except self.__sqlite.OperationalError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex))
            return None

    def execute(self, query):
        try:
            self.cursor.execute(getText(query))
        except self.__sqlite.OperationalError as ex:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) '%s'" % getSafeExString(ex))
        except self.__sqlite.DatabaseError as ex:
            raise SqlmapConnectionException(getSafeExString(ex))

        self.connector.commit()

    def select(self, query):
        self.execute(query)
        return self.fetchall()
