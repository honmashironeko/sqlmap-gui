#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import hashDBWrite
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import OS
from lib.core.settings import SUPPORTED_DBMS

def setDbms(dbms):
    """
    @param dbms: database management system to be set into the knowledge
    base as fingerprint.
    @type dbms: C{str}
    """

    hashDBWrite(HASHDB_KEYS.DBMS, dbms)

    _ = "(%s)" % ('|'.join(SUPPORTED_DBMS))
    _ = re.search(r"\A%s( |\Z)" % _, dbms, re.I)

    if _:
        dbms = _.group(1)

    Backend.setDbms(dbms)
    if kb.resolutionDbms:
        hashDBWrite(HASHDB_KEYS.DBMS, kb.resolutionDbms)

    logger.info("后端DBMS是 %s" % Backend.getDbms())

def setOs():
    """
    Example of kb.bannerFp dictionary:

    {
      'sp': set(['Service Pack 4']),
      'dbmsVersion': '8.00.194',
      'dbmsServicePack': '0',
      'distrib': set(['2000']),
      'dbmsRelease': '2000',
      'type': set(['Windows'])
    }
    """

    infoMsg = ""

    if not kb.bannerFp:
        return

    if "type" in kb.bannerFp:
        Backend.setOs(Format.humanize(kb.bannerFp["type"]))
        infoMsg = "后端数据库管理系统的操作系统是 %s" % Backend.getOs()

    if "distrib" in kb.bannerFp:
        kb.osVersion = Format.humanize(kb.bannerFp["distrib"])
        infoMsg += " %s" % kb.osVersion

    if "sp" in kb.bannerFp:
        kb.osSP = int(Format.humanize(kb.bannerFp["sp"]).replace("Service Pack ", ""))

    elif "sp" not in kb.bannerFp and Backend.isOs(OS.WINDOWS):
        kb.osSP = 0

    if Backend.getOs() and kb.osVersion and kb.osSP:
        infoMsg += " 服务包 %d" % kb.osSP

    if infoMsg:
        logger.info(infoMsg)

    hashDBWrite(HASHDB_KEYS.OS, Backend.getOs())
