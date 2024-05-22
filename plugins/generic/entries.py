#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.bigarray import BigArray
from lib.core.common import Backend
from lib.core.common import clearConsoleLine
from lib.core.common import getLimitRange
from lib.core.common import getSafeExString
from lib.core.common import isInferenceAvailable
from lib.core.common import isListLike
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import prioritySortColumns
from lib.core.common import readInput
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.convert import getConsoleLength
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dicts import DUMP_REPLACEMENTS
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.settings import CHECK_ZERO_COLUMNS_THRESHOLD
from lib.core.settings import CURRENT_DB
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import NULL
from lib.core.settings import PLUS_ONE_DBMSES
from lib.core.settings import UPPER_CASE_DBMSES
from lib.request import inject
from lib.utils.hash import attackDumpedTable
from lib.utils.pivotdumptable import pivotDumpTable
from thirdparty import six
from thirdparty.six.moves import zip as _zip

class Entries(object):
    """
    这个类为插件定义了枚举功能的条目。
    """

    def __init__(self):
        pass

    def dumpTable(self, foundData=None):
        self.forceDbmsEnum()

        if conf.db is None or conf.db == CURRENT_DB:
            if conf.db is None:
                warnMsg = "缺少数据库参数。sqlmap将使用当前数据库来枚举表条目"
                logger.warning(warnMsg)

            conf.db = self.getCurrentDb()

        elif conf.db is not None:
            if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
                conf.db = conf.db.upper()

            if ',' in conf.db:
                errMsg = "在枚举表的列时,只允许一个数据库名称"
                raise SqlmapMissingMandatoryOptionException(errMsg)

            if conf.exclude and re.search(conf.exclude, conf.db, re.I) is not None:
                infoMsg = "跳过数据库'%s'" % unsafeSQLIdentificatorNaming(conf.db)
                singleTimeLogMessage(infoMsg)
                return

        conf.db = safeSQLIdentificatorNaming(conf.db) or ""

        if conf.tbl:
            if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
                conf.tbl = conf.tbl.upper()

            tblList = conf.tbl.split(',')
        else:
            self.getTables()

            if len(kb.data.cachedTables) > 0:
                tblList = list(six.itervalues(kb.data.cachedTables))

                if tblList and isListLike(tblList[0]):
                    tblList = tblList[0]
            elif conf.db and not conf.search:
                errMsg = "无法检索数据库'%s'中的表" % unsafeSQLIdentificatorNaming(conf.db)
                raise SqlmapNoneDataException(errMsg)
            else:
                return

        for tbl in tblList:
            tblList[tblList.index(tbl)] = safeSQLIdentificatorNaming(tbl, True)

        for tbl in tblList:
            if kb.dumpKeyboardInterrupt:
                break

            if conf.exclude and re.search(conf.exclude, tbl, re.I) is not None:
                infoMsg = "跳过表'%s'" % unsafeSQLIdentificatorNaming(tbl)
                singleTimeLogMessage(infoMsg)
                continue

            conf.tbl = tbl
            kb.data.dumpedTable = {}

            if foundData is None:
                kb.data.cachedColumns = {}
                self.getColumns(onlyColNames=True, dumpMode=True)
            else:
                kb.data.cachedColumns = foundData

            try:
                if Backend.isDbms(DBMS.INFORMIX):
                    kb.dumpTable = "%s:%s" % (conf.db, tbl)
                elif Backend.isDbms(DBMS.SQLITE):
                    kb.dumpTable = tbl
                else:
                    kb.dumpTable = "%s.%s" % (conf.db, tbl)

                if safeSQLIdentificatorNaming(conf.db) not in kb.data.cachedColumns or safeSQLIdentificatorNaming(tbl, True) not in kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] or not kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)]:
                    warnMsg = "无法枚举表'%s'的列" % unsafeSQLIdentificatorNaming(tbl)
                    if METADB_SUFFIX not in conf.db:
                        warnMsg += "在数据库'%s'中" % unsafeSQLIdentificatorNaming(conf.db)
                    warnMsg += ",跳过"
                    logger.warning(warnMsg)

                    continue

                columns = kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)]
                colList = sorted(column for column in columns if column)

                if conf.exclude:
                    colList = [_ for _ in colList if re.search(conf.exclude, _, re.I) is None]

                if not colList:
                    warnMsg = "跳过表'%s'" % unsafeSQLIdentificatorNaming(tbl)
                    if METADB_SUFFIX not in conf.db:
                        warnMsg += "在数据库'%s'中" % unsafeSQLIdentificatorNaming(conf.db)
                    warnMsg += "(没有可用的列名)"
                    logger.warning(warnMsg)
                    continue

                kb.dumpColumns = [unsafeSQLIdentificatorNaming(_) for _ in colList]
                colNames = colString = ','.join(column for column in colList)
                rootQuery = queries[Backend.getIdentifiedDbms()].dump_table

                infoMsg = "获取条目"
                if conf.col:
                    infoMsg += "的列'%s'" % colNames
                infoMsg += "的表'%s'" % unsafeSQLIdentificatorNaming(tbl)
                if METADB_SUFFIX not in conf.db:
                    infoMsg += "在数据库'%s'中" % unsafeSQLIdentificatorNaming(conf.db)
                logger.info(infoMsg)

                for column in colList:
                    _ = agent.preprocessField(tbl, column)
                    if _ != column:
                        colString = re.sub(r"\b%s\b" % re.escape(column), _.replace("\\", r"\\"), colString)

                entriesCount = 0

                if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
                    entries = []
                    query = None

                    if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.DERBY, DBMS.ALTIBASE, DBMS.MIMERSQL):
                        query = rootQuery.inband.query % (colString, tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), tbl.upper())))
                    elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD, DBMS.MAXDB, DBMS.MCKOI, DBMS.EXTREMEDB, DBMS.RAIMA):
                        query = rootQuery.inband.query % (colString, tbl)
                    elif Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MSSQL):
                        # 部分inband和error
                        if not (isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) and kb.injection.data[PAYLOAD.TECHNIQUE.UNION].where == PAYLOAD.WHERE.ORIGINAL):
                            table = "%s.%s" % (conf.db, tbl) if conf.db else tbl

                            if Backend.isDbms(DBMS.MSSQL) and not conf.forcePivoting:
                                warnMsg = "在表转储出现问题时(例如列条目顺序),建议您重新运行使用'--force-pivoting'"
                                singleTimeWarnMessage(warnMsg)

                                query = rootQuery.blind.count % table
                                query = agent.whereQuery(query)

                                count = inject.getValue(query, blind=False, time=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)
                                if isNumPosStrValue(count):
                                    try:
                                        indexRange = getLimitRange(count, plusOne=True)

                                        for index in indexRange:
                                            row = []
                                            for column in colList:
                                                query = rootQuery.blind.query3 % (column, column, table, index)
                                                query = agent.whereQuery(query)
                                                value = inject.getValue(query, blind=False, time=False, dump=True) or ""
                                                row.append(value)

                                            if not entries and isNoneValue(row):
                                                break

                                            entries.append(row)

                                    except KeyboardInterrupt:
                                        kb.dumpKeyboardInterrupt = True
                                        clearConsoleLine()
                                        warnMsg = "在转储阶段检测到Ctrl+C"
                                        logger.warning(warnMsg)

                            if isNoneValue(entries) and not kb.dumpKeyboardInterrupt:
                                try:
                                    retVal = pivotDumpTable(table, colList, blind=False)
                                except KeyboardInterrupt:
                                    retVal = None
                                    kb.dumpKeyboardInterrupt = True
                                    clearConsoleLine()
                                    warnMsg = "在转储阶段检测到Ctrl+C"
                                    logger.warning(warnMsg)

                                if retVal:
                                    entries, _ = retVal
                                    entries = BigArray(_zip(*[entries[colName] for colName in colList]))
                        else:
                            query = rootQuery.inband.query % (colString, conf.db, tbl)
                    elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.HSQLDB, DBMS.H2, DBMS.VERTICA, DBMS.PRESTO, DBMS.CRATEDB, DBMS.CACHE, DBMS.VIRTUOSO, DBMS.CLICKHOUSE):
                        query = rootQuery.inband.query % (colString, conf.db, tbl, prioritySortColumns(colList)[0])
                    else:
                        query = rootQuery.inband.query % (colString, conf.db, tbl)

                    query = agent.whereQuery(query)

                    if not entries and query and not kb.dumpKeyboardInterrupt:
                        try:
                            entries = inject.getValue(query, blind=False, time=False, dump=True)
                        except KeyboardInterrupt:
                            entries = None
                            kb.dumpKeyboardInterrupt = True
                            clearConsoleLine()
                            warnMsg = "在转储阶段检测到Ctrl+C"
                            logger.warning(warnMsg)

                    if not isNoneValue(entries):
                        if isinstance(entries, six.string_types):
                            entries = [entries]
                        elif not isListLike(entries):
                            entries = []

                        entriesCount = len(entries)

                        for index, column in enumerate(colList):
                            if column not in kb.data.dumpedTable:
                                kb.data.dumpedTable[column] = {"length": len(column), "values": BigArray()}

                            for entry in entries:
                                if entry is None or len(entry) == 0:
                                    continue

                                if isinstance(entry, six.string_types):
                                    colEntry = entry
                                else:
                                    colEntry = unArrayizeValue(entry[index]) if index < len(entry) else u''

                                maxLen = max(getConsoleLength(column), getConsoleLength(DUMP_REPLACEMENTS.get(getUnicode(colEntry), getUnicode(colEntry))))

                                if maxLen > kb.data.dumpedTable[column]["length"]:
                                    kb.data.dumpedTable[column]["length"] = maxLen

                                kb.data.dumpedTable[column]["values"].append(colEntry)

                if not kb.data.dumpedTable and isInferenceAvailable() and not conf.direct:
                    infoMsg = "获取"
                    if conf.col:
                        infoMsg += "列'%s' " % colNames
                    infoMsg += "的条目数"
                    infoMsg += "在表'%s' " % unsafeSQLIdentificatorNaming(tbl)
                    infoMsg += "在数据库'%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    logger.info(infoMsg)

                    if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.DERBY, DBMS.ALTIBASE, DBMS.MIMERSQL):
                        query = rootQuery.blind.count % (tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), tbl.upper())))
                    elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.MAXDB, DBMS.ACCESS, DBMS.FIREBIRD, DBMS.MCKOI, DBMS.EXTREMEDB, DBMS.RAIMA):
                        query = rootQuery.blind.count % tbl
                    elif Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MSSQL):
                        query = rootQuery.blind.count % ("%s.%s" % (conf.db, tbl)) if conf.db else tbl
                    elif Backend.isDbms(DBMS.INFORMIX):
                        query = rootQuery.blind.count % (conf.db, tbl)
                    else:
                        query = rootQuery.blind.count % (conf.db, tbl)

                    query = agent.whereQuery(query)

                    count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                    lengths = {}
                    entries = {}

                    if count == 0:
                        warnMsg = "表'%s' " % unsafeSQLIdentificatorNaming(tbl)
                        warnMsg += "在数据库'%s' " % unsafeSQLIdentificatorNaming(conf.db)
                        warnMsg += "似乎为空"
                        logger.warning(warnMsg)

                        for column in colList:
                            lengths[column] = len(column)
                            entries[column] = []

                    elif not isNumPosStrValue(count):
                        warnMsg = "无法获取"
                        if conf.col:
                            warnMsg += "列'%s' " % colNames
                        warnMsg += "的条目数"
                        warnMsg += "在表'%s' " % unsafeSQLIdentificatorNaming(tbl)
                        warnMsg += "在数据库'%s'" % unsafeSQLIdentificatorNaming(conf.db)
                        logger.warning(warnMsg)

                        continue

                    elif Backend.getIdentifiedDbms() in (DBMS.ACCESS, DBMS.SYBASE, DBMS.MAXDB, DBMS.MSSQL, DBMS.INFORMIX, DBMS.MCKOI, DBMS.RAIMA):
                        if Backend.getIdentifiedDbms() in (DBMS.ACCESS, DBMS.MCKOI, DBMS.RAIMA):
                            table = tbl
                        elif Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MSSQL, DBMS.MAXDB):
                            table = "%s.%s" % (conf.db, tbl) if conf.db else tbl
                        elif Backend.isDbms(DBMS.INFORMIX):
                            table = "%s:%s" % (conf.db, tbl) if conf.db else tbl

                        if Backend.isDbms(DBMS.MSSQL) and not conf.forcePivoting:
                            warnMsg = "在转储表时出现问题(例如列条目顺序),建议您重新运行使用'--force-pivoting'"
                            singleTimeWarnMessage(warnMsg)

                            try:
                                indexRange = getLimitRange(count, plusOne=True)

                                for index in indexRange:
                                    for column in colList:
                                        query = rootQuery.blind.query3 % (column, column, table, index)
                                        query = agent.whereQuery(query)

                                        value = inject.getValue(query, union=False, error=False, dump=True) or ""

                                        if column not in lengths:
                                            lengths[column] = 0

                                        if column not in entries:
                                            entries[column] = BigArray()

                                        lengths[column] = max(lengths[column], len(DUMP_REPLACEMENTS.get(getUnicode(value), getUnicode(value))))
                                        entries[column].append(value)

                            except KeyboardInterrupt:
                                kb.dumpKeyboardInterrupt = True
                                clearConsoleLine()
                                warnMsg = "在转储阶段检测到Ctrl+C"
                                logger.warning(warnMsg)

                        if not entries and not kb.dumpKeyboardInterrupt:
                            try:
                                retVal = pivotDumpTable(table, colList, count, blind=True)
                            except KeyboardInterrupt:
                                retVal = None
                                kb.dumpKeyboardInterrupt = True
                                clearConsoleLine()
                                warnMsg = "在转储阶段检测到Ctrl+C"
                                logger.warning(warnMsg)

                            if retVal:
                                entries, lengths = retVal

                    else:
                        emptyColumns = []
                        plusOne = Backend.getIdentifiedDbms() in PLUS_ONE_DBMSES
                        indexRange = getLimitRange(count, plusOne=plusOne)

                        if len(colList) < len(indexRange) > CHECK_ZERO_COLUMNS_THRESHOLD:
                            debugMsg = "检查空列"
                            logger.debug(infoMsg)

                            for column in colList:
                                if not inject.checkBooleanExpression("(SELECT COUNT(%s) FROM %s)>0" % (column, kb.dumpTable)):
                                    emptyColumns.append(column)
                                    debugMsg = "表'%s'的列'%s' " % (kb.dumpTable, column)
                                    debugMsg += "将不会被转储,因为它似乎为空"
                                    logger.debug(debugMsg)

                        try:
                            for index in indexRange:
                                for column in colList:
                                    value = ""

                                    if column not in lengths:
                                        lengths[column] = 0

                                    if column not in entries:
                                        entries[column] = BigArray()

                                    if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.HSQLDB, DBMS.H2, DBMS.VERTICA, DBMS.PRESTO, DBMS.CRATEDB, DBMS.CACHE, DBMS.CLICKHOUSE):
                                        query = rootQuery.blind.query % (agent.preprocessField(tbl, column), conf.db, conf.tbl, sorted(colList, key=len)[0], index)
                                    elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.DERBY, DBMS.ALTIBASE,):
                                        query = rootQuery.blind.query % (agent.preprocessField(tbl, column), tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), tbl.upper())), index)
                                    elif Backend.getIdentifiedDbms() in (DBMS.MIMERSQL,):
                                        query = rootQuery.blind.query % (agent.preprocessField(tbl, column), tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), tbl.upper())), sorted(colList, key=len)[0], index)
                                    elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.EXTREMEDB):
                                        query = rootQuery.blind.query % (agent.preprocessField(tbl, column), tbl, index)
                                    elif Backend.isDbms(DBMS.FIREBIRD):
                                        query = rootQuery.blind.query % (index, agent.preprocessField(tbl, column), tbl)
                                    elif Backend.getIdentifiedDbms() in (DBMS.INFORMIX, DBMS.VIRTUOSO):
                                        query = rootQuery.blind.query % (index, agent.preprocessField(tbl, column), conf.db, tbl, sorted(colList, key=len)[0])
                                    elif Backend.isDbms(DBMS.FRONTBASE):
                                        query = rootQuery.blind.query % (index, agent.preprocessField(tbl, column), conf.db, tbl)
                                    else:
                                        query = rootQuery.blind.query % (agent.preprocessField(tbl, column), conf.db, tbl, index)

                                    query = agent.whereQuery(query)

                                    value = NULL if column in emptyColumns else inject.getValue(query, union=False, error=False, dump=True)
                                    value = '' if value is None else value

                                    lengths[column] = max(lengths[column], len(DUMP_REPLACEMENTS.get(getUnicode(value), getUnicode(value))))
                                    entries[column].append(value)

                        except KeyboardInterrupt:
                            kb.dumpKeyboardInterrupt = True
                            clearConsoleLine()
                            warnMsg = "在转储阶段检测到Ctrl+C"
                            logger.warning(warnMsg)

                    for column, columnEntries in entries.items():
                        length = max(lengths[column], len(column))

                        kb.data.dumpedTable[column] = {"length": length, "values": columnEntries}

                        entriesCount = len(columnEntries)

                if len(kb.data.dumpedTable) == 0 or (entriesCount == 0 and kb.permissionFlag):
                    warnMsg = "无法获取"
                    if conf.col:
                        warnMsg += "列'%s' " % colNames
                    warnMsg += "的条目"
                    warnMsg += "在表'%s' " % unsafeSQLIdentificatorNaming(tbl)
                    warnMsg += "在数据库'%s'%s" % (unsafeSQLIdentificatorNaming(conf.db), "(权限被拒绝)" if kb.permissionFlag else "")
                    logger.warning(warnMsg)
                else:
                    kb.data.dumpedTable["__infos__"] = {"count": entriesCount,
                                                        "table": safeSQLIdentificatorNaming(tbl, True),
                                                        "db": safeSQLIdentificatorNaming(conf.db)}
                    try:
                        attackDumpedTable()
                    except (IOError, OSError) as ex:
                        errMsg = "在攻击表转储时发生错误('%s')" % getSafeExString(ex)
                        logger.critical(errMsg)
                    conf.dumper.dbTableValues(kb.data.dumpedTable)

            except SqlmapConnectionException as ex:
                errMsg = "在转储阶段检测到连接异常('%s')" % getSafeExString(ex)
                logger.critical(errMsg)

            finally:
                kb.dumpColumns = None
                kb.dumpTable = None

    def dumpAll(self):
        if conf.db is not None and conf.tbl is None:
            self.dumpTable()
            return

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            errMsg = "information_schema不可用,后端DBMS是MySQL < 5.0"
            raise SqlmapUnsupportedFeatureException(errMsg)

        infoMsg = "sqlmap现在将转储所有数据库中的所有表的条目"
        logger.info(infoMsg)

        conf.tbl = None
        conf.col = None

        self.getTables()

        if kb.data.cachedTables:
            if isinstance(kb.data.cachedTables, list):
                kb.data.cachedTables = {None: kb.data.cachedTables}

            for db, tables in kb.data.cachedTables.items():
                conf.db = db

                for table in tables:
                    if conf.exclude and re.search(conf.exclude, table, re.I) is not None:
                        infoMsg = "跳过表'%s'" % unsafeSQLIdentificatorNaming(table)
                        logger.info(infoMsg)
                        continue

                    try:
                        conf.tbl = table
                        kb.data.cachedColumns = {}
                        kb.data.dumpedTable = {}

                        self.dumpTable()
                    except SqlmapNoneDataException:
                        infoMsg = "跳过表'%s'" % unsafeSQLIdentificatorNaming(table)
                        logger.info(infoMsg)

    def dumpFoundColumn(self, dbs, foundCols, colConsider):
        message = "您是否要转储找到的列的条目？[Y/n] "

        if not readInput(message, default='Y', boolean=True):
            return

        dumpFromDbs = []
        message = "哪个数据库？\n[a]ll(默认)\n"

        for db, tblData in dbs.items():
            if tblData:
                message += "[%s]\n" % unsafeSQLIdentificatorNaming(db)

        message += "[q]uit"
        choice = readInput(message, default='a')

        if not choice or choice in ('a', 'A'):
            dumpFromDbs = list(dbs.keys())
        elif choice in ('q', 'Q'):
            return
        else:
            dumpFromDbs = choice.replace(" ", "").split(',')

        for db, tblData in dbs.items():
            if db not in dumpFromDbs or not tblData:
                continue

            conf.db = db
            dumpFromTbls = []
            message = "数据库'%s'的哪些表？\n" % unsafeSQLIdentificatorNaming(db)
            message += "[a]ll(默认)\n"

            for tbl in tblData:
                message += "[%s]\n" % tbl

            message += "[s]kip\n"
            message += "[q]uit"
            choice = readInput(message, default='a')

            if not choice or choice in ('a', 'A'):
                dumpFromTbls = tblData
            elif choice in ('s', 'S'):
                continue
            elif choice in ('q', 'Q'):
                return
            else:
                dumpFromTbls = choice.replace(" ", "").split(',')

            for table, columns in tblData.items():
                if table not in dumpFromTbls:
                    continue

                conf.tbl = table
                colList = [_ for _ in columns if _]

                if conf.exclude:
                    colList = [_ for _ in colList if re.search(conf.exclude, _, re.I) is None]

                conf.col = ','.join(colList)
                kb.data.cachedColumns = {}
                kb.data.dumpedTable = {}

                data = self.dumpTable(dbs)

                if data:
                    conf.dumper.dbTableValues(data)

    def dumpFoundTables(self, tables):
        message = "您是否要转储找到的表的条目？[Y/n] "

        if not readInput(message, default='Y', boolean=True):
            return

        dumpFromDbs = []
        message = "哪个数据库？\n[a]ll(默认)\n"

        for db, tablesList in tables.items():
            if tablesList:
                message += "[%s]\n" % unsafeSQLIdentificatorNaming(db)

        message += "[q]uit"
        choice = readInput(message, default='a')

        if not choice or choice.lower() == 'a':
            dumpFromDbs = list(tables.keys())
        elif choice.lower() == 'q':
            return
        else:
            dumpFromDbs = choice.replace(" ", "").split(',')

        for db, tablesList in tables.items():
            if db not in dumpFromDbs or not tablesList:
                continue

            conf.db = db
            dumpFromTbls = []
            message = "数据库'%s'的哪些表？\n" % unsafeSQLIdentificatorNaming(db)
            message += "[a]ll(默认)\n"

            for tbl in tablesList:
                message += "[%s]\n" % unsafeSQLIdentificatorNaming(tbl)

            message += "[s]kip\n"
            message += "[q]uit"
            choice = readInput(message, default='a')

            if not choice or choice.lower() == 'a':
                dumpFromTbls = tablesList
            elif choice.lower() == 's':
                continue
            elif choice.lower() == 'q':
                return
            else:
                dumpFromTbls = choice.replace(" ", "").split(',')

            for table in dumpFromTbls:
                conf.tbl = table
                kb.data.cachedColumns = {}
                kb.data.dumpedTable = {}

                data = self.dumpTable()

                if data:
                    conf.dumper.dbTableValues(data)