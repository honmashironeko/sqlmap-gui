#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.dicts import DBMS_DICT
from lib.core.enums import DBMS
from lib.core.settings import IS_WIN

def checkDependencies():
    missing_libraries = set()

    for dbmsName, data in DBMS_DICT.items():
        if data[1] is None:
            continue

        try:
            if dbmsName in (DBMS.MSSQL, DBMS.SYBASE):
                __import__("_mssql")

                pymssql = __import__("pymssql")
                if not hasattr(pymssql, "__version__") or pymssql.__version__ < "1.0.2":
                    warnMsg = "'%s' 第三方库的版本必须大于等于 1.0.2 才能正常工作。请从 '%s' 下载" % (data[1], data[2])
                    logger.warning(warnMsg)
            elif dbmsName == DBMS.MYSQL:
                __import__("pymysql")
            elif dbmsName in (DBMS.PGSQL, DBMS.CRATEDB):
                __import__("psycopg2")
            elif dbmsName == DBMS.ORACLE:
                __import__("cx_Oracle")
            elif dbmsName == DBMS.SQLITE:
                __import__("sqlite3")
            elif dbmsName == DBMS.ACCESS:
                __import__("pyodbc")
            elif dbmsName == DBMS.FIREBIRD:
                __import__("kinterbasdb")
            elif dbmsName == DBMS.DB2:
                __import__("ibm_db_dbi")
            elif dbmsName in (DBMS.HSQLDB, DBMS.CACHE):
                __import__("jaydebeapi")
                __import__("jpype")
            elif dbmsName == DBMS.INFORMIX:
                __import__("ibm_db_dbi")
            elif dbmsName == DBMS.MONETDB:
                __import__("pymonetdb")
            elif dbmsName == DBMS.DERBY:
                __import__("drda")
            elif dbmsName == DBMS.VERTICA:
                __import__("vertica_python")
            elif dbmsName == DBMS.PRESTO:
                __import__("prestodb")
            elif dbmsName == DBMS.MIMERSQL:
                __import__("mimerpy")
            elif dbmsName == DBMS.CUBRID:
                __import__("CUBRIDdb")
            elif dbmsName == DBMS.CLICKHOUSE:
                __import__("clickhouse_connect")       
        except:
            warnMsg = "sqlmap需要 '%s' 第三方库才能直接连接到数据库管理系统 '%s'。请从 '%s' 下载" % (data[1], dbmsName, data[2])
            logger.warning(warnMsg)
            missing_libraries.add(data[1])

            continue

        debugMsg = "找到了 '%s' 第三方库" % data[1]
        logger.debug(debugMsg)

    try:
        __import__("impacket")
        debugMsg = "找到了 'python-impacket' 第三方库"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "sqlmap需要 'python-impacket' 第三方库以支持带外接管功能。请从 'https://github.com/coresecurity/impacket' 下载"
        logger.warning(warnMsg)
        missing_libraries.add('python-impacket')

    try:
        __import__("ntlm")
        debugMsg = "找到了 'python-ntlm' 第三方库"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "如果您计划攻击一个使用NTLM身份验证的Web应用程序,sqlmap需要 'python-ntlm' 第三方库。请从 'https://github.com/mullender/python-ntlm' 下载"
        logger.warning(warnMsg)
        missing_libraries.add('python-ntlm')

    try:
        __import__("websocket._abnf")
        debugMsg = "'websocket-client' library is found"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "如果您计划攻击一个使用WebSocket的Web应用程序,sqlmap需要 'websocket-client' 第三方库。请从 'https://pypi.python.org/pypi/websocket-client/' 下载"
        logger.warning(warnMsg)
        missing_libraries.add('websocket-client')

    try:
        __import__("tkinter")
        debugMsg = "找到了 'tkinter' 库"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "如果您计划运行GUI界面,sqlmap需要 'tkinter' 库"
        logger.warning(warnMsg)
        missing_libraries.add('tkinter')

    try:
        __import__("tkinter.ttk")
        debugMsg = "找到了 'tkinter.ttk' 库"
        logger.debug(debugMsg)
    except ImportError:
        warnMsg = "如果您计划运行GUI界面,sqlmap需要 'tkinter.ttk' 库"
        logger.warning(warnMsg)
        missing_libraries.add('tkinter.ttk')

    if IS_WIN:
        try:
            __import__("pyreadline")
            debugMsg = "找到了 'python-pyreadline' 第三方库"
            logger.debug(debugMsg)
        except ImportError:
            warnMsg = "sqlmap需要 'pyreadline' 第三方库才能在SQL shell和OS shell中使用sqlmap的TAB补全和历史记录支持功能。请从 'https://pypi.org/project/pyreadline/' 下载"
            logger.warning(warnMsg)
            missing_libraries.add('python-pyreadline')

    if len(missing_libraries) == 0:
        infoMsg = "所有依赖项已安装"
        logger.info(infoMsg)
