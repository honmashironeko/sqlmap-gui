#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import sqlite3

from lib.core.common import cleanReplaceUnicode
from lib.core.common import getSafeExString
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapValueException
from lib.core.settings import UNICODE_ENCODING
from lib.utils.safe2bin import safechardecode

class Replication(object):
    """
    This class holds all methods/classes used for database
    replication purposes.
    """

    def __init__(self, dbpath):
        try:
            self.dbpath = dbpath
            self.connection = sqlite3.connect(dbpath)
            self.connection.isolation_level = None
            self.cursor = self.connection.cursor()
        except sqlite3.OperationalError as ex:
            errMsg = "打开复制文件 '%s' 时发生错误 ('%s')" % (dbpath, getSafeExString(ex))
            raise SqlmapConnectionException(errMsg)

    class DataType(object):
        """
        Using this class we define auxiliary objects
        used for representing sqlite data types.
        """

        def __init__(self, name):
            self.name = name

        def __str__(self):
            return self.name

        def __repr__(self):
            return "<DataType: %s>" % self

    class Table(object):
        """
        This class defines methods used to manipulate table objects.
        """

        def __init__(self, parent, name, columns=None, create=True, typeless=False):
            self.parent = parent
            self.name = unsafeSQLIdentificatorNaming(name)
            self.columns = columns
            if create:
                try:
                    self.execute('DROP TABLE IF EXISTS "%s"' % self.name)
                    if not typeless:
                        self.execute('CREATE TABLE "%s" (%s)' % (self.name, ','.join('"%s" %s' % (unsafeSQLIdentificatorNaming(colname), coltype) for colname, coltype in self.columns)))
                    else:
                        self.execute('CREATE TABLE "%s" (%s)' % (self.name, ','.join('"%s"' % unsafeSQLIdentificatorNaming(colname) for colname in self.columns)))
                except Exception as ex:
                    errMsg = "在初始化位于 '%s' 的 SQLite 数据库时发生问题 ('%s')" % (self.parent.dbpath, getSafeExString(ex, UNICODE_ENCODING))
                    raise SqlmapGenericException(errMsg)

        def insert(self, values):
            """
            This function is used for inserting row(s) into current table.
            """

            if len(values) == len(self.columns):
                self.execute('INSERT INTO "%s" VALUES (%s)' % (self.name, ','.join(['?'] * len(values))), safechardecode(values))
            else:
                errMsg = "在复制插入操作中使用了错误的列数"
                raise SqlmapValueException(errMsg)

        def execute(self, sql, parameters=None):
            try:
                try:
                    self.parent.cursor.execute(sql, parameters or [])
                except UnicodeError:
                    self.parent.cursor.execute(sql, cleanReplaceUnicode(parameters or []))
            except sqlite3.OperationalError as ex:
                errMsg = "访问位于 '%s' 的 SQLite 数据库时发生问题 ('%s')。请确保它没有被其他程序使用" % (self.parent.dbpath, getSafeExString(ex, UNICODE_ENCODING))
                raise SqlmapGenericException(errMsg)

        def beginTransaction(self):
            """
            Great speed improvement can be gained by using explicit transactions around multiple inserts.
            Reference: http://stackoverflow.com/questions/4719836/python-and-sqlite3-adding-thousands-of-rows
            """
            self.execute('BEGIN TRANSACTION')

        def endTransaction(self):
            self.execute('END TRANSACTION')

        def select(self, condition=None):
            """
            This function is used for selecting row(s) from current table.
            """
            _ = 'SELECT * FROM %s' % self.name
            if condition:
                _ += 'WHERE %s' % condition
            return self.execute(_)

    def createTable(self, tblname, columns=None, typeless=False):
        """
        This function creates Table instance with current connection settings.
        """
        return Replication.Table(parent=self, name=tblname, columns=columns, typeless=typeless)

    def __del__(self):
        self.cursor.close()
        self.connection.close()

    # sqlite data types
    NULL = DataType('NULL')
    INTEGER = DataType('INTEGER')
    REAL = DataType('REAL')
    TEXT = DataType('TEXT')
    BLOB = DataType('BLOB')
