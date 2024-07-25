#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import re
import sys

from lib.core.common import Backend
from lib.core.common import dataToStdout
from lib.core.common import getSQLSnippet
from lib.core.common import isStackingAvailable
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.dicts import SQL_STATEMENTS
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.enums import DBMS
from lib.core.exception import SqlmapNoneDataException
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import NULL
from lib.core.settings import PARAMETER_SPLITTING_REGEX
from lib.core.shell import autoCompletion
from lib.request import inject
from thirdparty.six.moves import input as _input

class Custom(object):
    """
    这个类为插件定义了自定义枚举功能。
    """

    def __init__(self):
        pass

    def sqlQuery(self, query):
        output = None
        sqlType = None
        query = query.rstrip(';')

        try:
            for sqlTitle, sqlStatements in SQL_STATEMENTS.items():
                for sqlStatement in sqlStatements:
                    if query.lower().startswith(sqlStatement):
                        sqlType = sqlTitle
                        break

            if not re.search(r"\b(OPENROWSET|INTO)\b", query, re.I) and (not sqlType or "SELECT" in sqlType):
                infoMsg = "获取 %s 查询结果: '%s'" % (sqlType if sqlType is not None else "SQL", query)
                logger.info(infoMsg)

                if Backend.isDbms(DBMS.MSSQL):
                    match = re.search(r"(\bFROM\s+)([^\s]+)", query, re.I)
                    if match and match.group(2).count('.') == 1:
                        query = query.replace(match.group(0), "%s%s" % (match.group(1), match.group(2).replace('.', ".dbo.")))

                query = re.sub(r"(?i)\w+%s\.?" % METADB_SUFFIX, "", query)

                output = inject.getValue(query, fromUser=True)

                return output
            elif not isStackingAvailable() and not conf.direct:
                warnMsg = "只有在支持堆叠查询时才能执行非查询SQL语句"
                logger.warning(warnMsg)

                return None
            else:
                if sqlType:
                    infoMsg = "执行 %s 语句: '%s'" % (sqlType if sqlType is not None else "SQL", query)
                else:
                    infoMsg = "执行未知的SQL命令: '%s'" % query
                logger.info(infoMsg)

                inject.goStacked(query)

                output = NULL

        except SqlmapNoneDataException as ex:
            logger.warning(ex)

        return output

    def sqlShell(self):
        infoMsg = "调用 %s shell。输入 'x' 或 'q' 退出" % Backend.getIdentifiedDbms()
        logger.info(infoMsg)

        autoCompletion(AUTOCOMPLETE_TYPE.SQL)

        while True:
            query = None

            try:
                query = _input("sql-shell> ")
                query = getUnicode(query, encoding=sys.stdin.encoding)
                query = query.strip("; ")
            except UnicodeDecodeError:
                print()
                errMsg = "无效的用户输入"
                logger.error(errMsg)
            except KeyboardInterrupt:
                print()
                errMsg = "用户中断"
                logger.error(errMsg)
            except EOFError:
                print()
                errMsg = "退出"
                logger.error(errMsg)
                break

            if not query:
                continue

            if query.lower() in ("x", "q", "exit", "quit"):
                break

            output = self.sqlQuery(query)

            if output and output != "Quit":
                conf.dumper.sqlQuery(query, output)

            elif not output:
                pass

            elif output != "Quit":
                dataToStdout("无输出\n")

    def sqlFile(self):
        infoMsg = "从给定的文件中执行SQL语句"
        logger.info(infoMsg)

        for filename in re.split(PARAMETER_SPLITTING_REGEX, conf.sqlFile):
            filename = filename.strip()

            if not filename:
                continue

            snippet = getSQLSnippet(Backend.getDbms(), filename)

            if snippet and all(query.strip().upper().startswith("SELECT") for query in (_ for _ in snippet.split(';' if ';' in snippet else '\n') if _)):
                for query in (_ for _ in snippet.split(';' if ';' in snippet else '\n') if _):
                    query = query.strip()
                    if query:
                        conf.dumper.sqlQuery(query, self.sqlQuery(query))
            else:
                conf.dumper.sqlQuery(snippet, self.sqlQuery(snippet))