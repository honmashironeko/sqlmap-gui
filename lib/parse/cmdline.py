#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import os
import re
import shlex
import sys

try:
    from optparse import OptionError as ArgumentError
    from optparse import OptionGroup
    from optparse import OptionParser as ArgumentParser
    from optparse import SUPPRESS_HELP as SUPPRESS

    ArgumentParser.add_argument = ArgumentParser.add_option

    def _add_argument_group(self, *args, **kwargs):
        return self.add_option_group(OptionGroup(self, *args, **kwargs))

    ArgumentParser.add_argument_group = _add_argument_group

    def _add_argument(self, *args, **kwargs):
        return self.add_option(*args, **kwargs)

    OptionGroup.add_argument = _add_argument

except ImportError:
    from argparse import ArgumentParser
    from argparse import ArgumentError
    from argparse import SUPPRESS

finally:
    def get_actions(instance):
        for attr in ("option_list", "_group_actions", "_actions"):
            if hasattr(instance, attr):
                return getattr(instance, attr)

    def get_groups(parser):
        return getattr(parser, "option_groups", None) or getattr(parser, "_action_groups")

    def get_all_options(parser):
        retVal = set()

        for option in get_actions(parser):
            if hasattr(option, "option_strings"):
                retVal.update(option.option_strings)
            else:
                retVal.update(option._long_opts)
                retVal.update(option._short_opts)

        for group in get_groups(parser):
            for option in get_actions(group):
                if hasattr(option, "option_strings"):
                    retVal.update(option.option_strings)
                else:
                    retVal.update(option._long_opts)
                    retVal.update(option._short_opts)

        return retVal

from lib.core.common import checkOldOptions
from lib.core.common import checkSystemEncoding
from lib.core.common import dataToStdout
from lib.core.common import expandMnemonics
from lib.core.common import getSafeExString
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import logger
from lib.core.defaults import defaults
from lib.core.dicts import DEPRECATED_OPTIONS
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.exception import SqlmapShellQuitException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSyntaxException
from lib.core.option import _createHomeDirectories
from lib.core.settings import BASIC_HELP_ITEMS
from lib.core.settings import DUMMY_URL
from lib.core.settings import IGNORED_OPTIONS
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import IS_WIN
from lib.core.settings import MAX_HELP_OPTION_LENGTH
from lib.core.settings import VERSION_STRING
from lib.core.shell import autoCompletion
from lib.core.shell import clearHistory
from lib.core.shell import loadHistory
from lib.core.shell import saveHistory
from thirdparty.six.moves import input as _input

def cmdLineParser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    checkSystemEncoding()

    # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
    _ = getUnicode(os.path.basename(argv[0]), encoding=sys.stdin.encoding)

    usage = "%s%s [options]" % ("%s " % os.path.basename(sys.executable) if not IS_WIN else "", "\"%s\"" % _ if " " in _ else _)
    parser = ArgumentParser(usage=usage)

    try:
        parser.add_argument("--hh", dest="advancedHelp", action="store_true",
            help="显示高级帮助消息并退出")

        parser.add_argument("--version", dest="showVersion", action="store_true",
            help="显示程序的版本号并退出")

        parser.add_argument("-v", dest="verbose", type=int,
            help="详细级别:0-6(默认为 %d)" % defaults.verbose)

        # Target options
        target = parser.add_argument_group("目标", "至少需要提供其中一个选项来定义目标")

        target.add_argument("-u", "--url", dest="url",
            help="目标URL (e.g. \"http://www.site.com/vuln.php?id=1\")")

        target.add_argument("-d", dest="direct",
            help="用于直接数据库连接的连接字符串")

        target.add_argument("-l", dest="logFile",
            help="从Burp或WebScarab代理日志文件中解析目标")

        target.add_argument("-m", dest="bulkFile",
            help="从文本文件中扫描多个目标")

        target.add_argument("-r", dest="requestFile",
            help="从文件中加载HTTP请求")

        target.add_argument("-g", dest="googleDork",
            help="将Google dork结果处理为目标URL")

        target.add_argument("-c", dest="configFile",
            help="从配置INI文件中加载选项")

        # Request options
        request = parser.add_argument_group("请求", "这些选项可用于指定如何连接到目标URL")

        request.add_argument("-A", "--user-agent", dest="agent",
            help="HTTP User-Agent头部的值")

        request.add_argument("-H", "--header", dest="header",
            help="额外的头部(例如\"X-Forwarded-For: 127.0.0.1\")")

        request.add_argument("--method", dest="method",
            help="强制使用给定的HTTP方法(例如PUT)")

        request.add_argument("--data", dest="data",
            help="要通过POST发送的数据字符串(例如\"id=1\")")

        request.add_argument("--param-del", dest="paramDel",
            help="用于分割参数值的字符(例如&)")

        request.add_argument("--cookie", dest="cookie",
            help="HTTP Cookie头部的值(例如\"PHPSESSID=a8d127e..\")")

        request.add_argument("--cookie-del", dest="cookieDel",
            help="用于分割cookie值的字符(例如;)")

        request.add_argument("--live-cookies", dest="liveCookies",
            help="用于加载最新值的实时cookie文件")

        request.add_argument("--load-cookies", dest="loadCookies",
            help="包含Netscape/wget格式cookie的文件")

        request.add_argument("--drop-set-cookie", dest="dropSetCookie", action="store_true",
            help="忽略响应中的Set-Cookie头部")

        request.add_argument("--mobile", dest="mobile", action="store_true",
            help="通过HTTP User-Agent头部模拟智能手机")

        request.add_argument("--random-agent", dest="randomAgent", action="store_true",
            help="使用随机选择的HTTP User-Agent头部值")

        request.add_argument("--host", dest="host",
            help="HTTP Host头部的值")

        request.add_argument("--referer", dest="referer",
            help="HTTP Referer头部的值")

        request.add_argument("--headers", dest="headers",
            help="额外的头部(例如\"Accept-Language: fr\\nETag: 123\")")

        request.add_argument("--auth-type", dest="authType",
            help="HTTP身份验证类型(Basic,Digest,Bearer等)")

        request.add_argument("--auth-cred", dest="authCred",
            help="HTTP身份验证凭据(用户名:密码)")

        request.add_argument("--auth-file", dest="authFile",
            help="HTTP身份验证PEM证书/私钥文件")

        request.add_argument("--abort-code", dest="abortCode",
            help="在(有问题的)HTTP错误代码上中止(例如401)")

        request.add_argument("--ignore-code", dest="ignoreCode",
            help="忽略(有问题的)HTTP错误代码(例如401)")

        request.add_argument("--ignore-proxy", dest="ignoreProxy", action="store_true",
            help="忽略系统默认代理设置")

        request.add_argument("--ignore-redirects", dest="ignoreRedirects", action="store_true",
            help="忽略重定向尝试")

        request.add_argument("--ignore-timeouts", dest="ignoreTimeouts", action="store_true",
            help="忽略连接超时")

        request.add_argument("--proxy", dest="proxy",
            help="使用代理连接到目标URL")

        request.add_argument("--proxy-cred", dest="proxyCred",
            help="代理身份验证凭据(用户名:密码)")

        request.add_argument("--proxy-file", dest="proxyFile",
            help="从文件中加载代理列表")

        request.add_argument("--proxy-freq", dest="proxyFreq", type=int,
            help="在给定列表中更改代理之间的请求次数")

        request.add_argument("--tor", dest="tor", action="store_true",
            help="使用Tor匿名网络")

        request.add_argument("--tor-port", dest="torPort",
            help="设置Tor代理端口(非默认值)")

        request.add_argument("--tor-type", dest="torType",
            help="设置Tor代理类型(HTTP,SOCKS4或SOCKS5(默认))")

        request.add_argument("--check-tor", dest="checkTor", action="store_true",
            help="检查Tor是否正确使用")

        request.add_argument("--delay", dest="delay", type=float,
            help="每个HTTP请求之间的延迟时间(秒)")

        request.add_argument("--timeout", dest="timeout", type=float,
            help="连接超时前等待的秒数(默认值%d)" % defaults.timeout)

        request.add_argument("--retries", dest="retries", type=int,
            help="连接超时时的重试次数(默认值%d)" % defaults.retries)

        request.add_argument("--retry-on", dest="retryOn",
            help="在正则表达式匹配内容时重试请求(例如\"drop\")")

        request.add_argument("--randomize", dest="rParam",
            help="随机更改给定参数的值")

        request.add_argument("--safe-url", dest="safeUrl",
            help="在测试期间频繁访问的URL地址")

        request.add_argument("--safe-post", dest="safePost",
            help="发送到安全URL的POST数据")

        request.add_argument("--safe-req", dest="safeReqFile",
            help="从文件中加载安全的HTTP请求")

        request.add_argument("--safe-freq", dest="safeFreq", type=int,
            help="在访问安全URL之间的常规请求次数")

        request.add_argument("--skip-urlencode", dest="skipUrlEncode", action="store_true",
            help="跳过对负载数据的URL编码")

        request.add_argument("--csrf-token", dest="csrfToken",
            help="用于保存反CSRF令牌的参数")

        request.add_argument("--csrf-url", dest="csrfUrl",
            help="用于提取反CSRF令牌的URL地址")

        request.add_argument("--csrf-method", dest="csrfMethod",
            help="在访问反CSRF令牌页面时使用的HTTP方法")

        request.add_argument("--csrf-data", dest="csrfData",
            help="在访问反CSRF令牌页面时发送的POST数据")

        request.add_argument("--csrf-retries", dest="csrfRetries", type=int,
            help="反CSRF令牌检索的重试次数(默认值%d)" % defaults.csrfRetries)

        request.add_argument("--force-ssl", dest="forceSSL", action="store_true",
            help="强制使用SSL/HTTPS")

        request.add_argument("--chunked", dest="chunked", action="store_true",
            help="使用HTTP分块传输编码(POST)请求")

        request.add_argument("--hpp", dest="hpp", action="store_true",
            help="使用HTTP参数污染方法")

        request.add_argument("--eval", dest="evalCode",
            help="在请求之前评估提供的Python代码(例如\"import hashlib;id2=hashlib.md5(id).hexdigest()\")")

        # Optimization options
        optimization = parser.add_argument_group("优化", "这些选项可用于优化sqlmap的性能")

        optimization.add_argument("-o", dest="optimize", action="store_true",
            help="打开所有优化开关")

        optimization.add_argument("--predict-output", dest="predictOutput", action="store_true",
            help="预测常见查询的输出")

        optimization.add_argument("--keep-alive", dest="keepAlive", action="store_true",
            help="使用持久的HTTP(s)连接")

        optimization.add_argument("--null-connection", dest="nullConnection", action="store_true",
            help="在没有实际HTTP响应体的情况下获取页面长度")

        optimization.add_argument("--threads", dest="threads", type=int,
            help="最大并发HTTP(s)请求数(默认值%d)" % defaults.threads)

        # Injection options
        injection = parser.add_argument_group("注入", "这些选项可用于指定要测试的参数,提供自定义的注入载荷和可选的篡改脚本")

        injection.add_argument("-p", dest="testParameter",
            help="可测试的参数")

        injection.add_argument("--skip", dest="skip",
            help="跳过对给定参数的测试")

        injection.add_argument("--skip-static", dest="skipStatic", action="store_true",
            help="跳过不显示为动态的参数的测试")

        injection.add_argument("--param-exclude", dest="paramExclude",
            help="用于排除测试的参数的正则表达式(例如\"ses\")")

        injection.add_argument("--param-filter", dest="paramFilter",
            help="按位置选择可测试的参数(例如\"POST\")")

        injection.add_argument("--dbms", dest="dbms",
            help="强制指定后端DBMS的值")

        injection.add_argument("--dbms-cred", dest="dbmsCred",
            help="DBMS身份验证凭据(用户名:密码)")

        injection.add_argument("--os", dest="os",
            help="强制指定后端DBMS的操作系统")

        injection.add_argument("--invalid-bignum", dest="invalidBignum", action="store_true",
            help="使用大数来使值无效")

        injection.add_argument("--invalid-logical", dest="invalidLogical", action="store_true",
            help="使用逻辑操作使值无效")

        injection.add_argument("--invalid-string", dest="invalidString", action="store_true",
            help="使用随机字符串使值无效")

        injection.add_argument("--no-cast", dest="noCast", action="store_true",
            help="关闭载荷转换机制")

        injection.add_argument("--no-escape", dest="noEscape", action="store_true",
            help="关闭字符串转义机制")

        injection.add_argument("--prefix", dest="prefix",
            help="注入载荷前缀字符串")

        injection.add_argument("--suffix", dest="suffix",
            help="注入载荷后缀字符串")

        injection.add_argument("--tamper", dest="tamper",
            help="使用给定的脚本对注入数据进行篡改")
        # Detection options
        detection = parser.add_argument_group("检测", "这些选项可用于自定义检测阶段")

        detection.add_argument("--level", dest="level", type=int,
            help="要执行的测试级别(1-5,默认值%d)" % defaults.level)

        detection.add_argument("--risk", dest="risk", type=int,
            help="要执行的测试风险级别(1-3,默认值%d)" % defaults.risk)

        detection.add_argument("--string", dest="string",
            help="当查询评估为True时要匹配的字符串")

        detection.add_argument("--not-string", dest="notString",
            help="当查询评估为False时要匹配的字符串")

        detection.add_argument("--regexp", dest="regexp",
            help="当查询评估为True时要匹配的正则表达式")

        detection.add_argument("--code", dest="code", type=int,
            help="当查询评估为True时要匹配的HTTP代码")

        detection.add_argument("--smart", dest="smart", action="store_true",
            help="仅在存在正面启发式时执行彻底的测试")

        detection.add_argument("--text-only", dest="textOnly", action="store_true",
            help="仅基于文本内容比较页面")

        detection.add_argument("--titles", dest="titles", action="store_true",
            help="仅基于页面标题比较页面")

        # Techniques options
        techniques = parser.add_argument_group("技术", "这些选项可用于调整特定SQL注入技术的测试")

        techniques.add_argument("--technique", dest="technique",
            help="要使用的SQL注入技术(默认值\"%s\")" % defaults.technique)

        techniques.add_argument("--time-sec", dest="timeSec", type=int,
            help="延迟DBMS响应的秒数(默认值%d)" % defaults.timeSec)

        techniques.add_argument("--union-cols", dest="uCols",
            help="要测试UNION查询SQL注入的列范围")

        techniques.add_argument("--union-char", dest="uChar",
            help="用于暴力破解列数的字符")

        techniques.add_argument("--union-from", dest="uFrom",
            help="在UNION查询SQL注入的FROM部分中使用的表")

        techniques.add_argument("--union-values", dest="uValues",
            help="用于UNION查询SQL注入的列值")

        techniques.add_argument("--dns-domain", dest="dnsDomain",
            help="用于DNS泄露攻击的域名")

        techniques.add_argument("--second-url", dest="secondUrl",
            help="搜索第二次响应的结果页面URL")

        techniques.add_argument("--second-req", dest="secondReq",
            help="从文件中加载第二次HTTP请求")

        # Fingerprint options
        fingerprint = parser.add_argument_group("指纹识别")

        fingerprint.add_argument("-f", "--fingerprint", dest="extensiveFp", action="store_true",
            help="执行详细的DBMS版本指纹识别")

        # Enumeration options
        enumeration = parser.add_argument_group("枚举", "这些选项可用于枚举后端数据库管理系统中的信息、结构和数据")

        enumeration.add_argument("-a", "--all", dest="getAll", action="store_true",
                    help="检索所有内容")

        enumeration.add_argument("-b", "--banner", dest="getBanner", action="store_true",
                    help="检索DBMS横幅")

        enumeration.add_argument("--current-user", dest="getCurrentUser", action="store_true",
                    help="检索DBMS当前用户")

        enumeration.add_argument("--current-db", dest="getCurrentDb", action="store_true",
                    help="检索DBMS当前数据库")

        enumeration.add_argument("--hostname", dest="getHostname", action="store_true",
                    help="检索DBMS服务器主机名")

        enumeration.add_argument("--is-dba", dest="isDba", action="store_true",
                    help="检测DBMS当前用户是否为DBA")

        enumeration.add_argument("--users", dest="getUsers", action="store_true",
                    help="枚举DBMS用户")

        enumeration.add_argument("--passwords", dest="getPasswordHashes", action="store_true",
                    help="枚举DBMS用户密码哈希值")

        enumeration.add_argument("--privileges", dest="getPrivileges", action="store_true",
                    help="枚举DBMS用户权限")

        enumeration.add_argument("--roles", dest="getRoles", action="store_true",
                    help="枚举DBMS用户角色")

        enumeration.add_argument("--dbs", dest="getDbs", action="store_true",
                    help="枚举DBMS数据库")

        enumeration.add_argument("--tables", dest="getTables", action="store_true",
                    help="枚举DBMS数据库表")

        enumeration.add_argument("--columns", dest="getColumns", action="store_true",
                    help="枚举DBMS数据库表列")

        enumeration.add_argument("--schema", dest="getSchema", action="store_true",
                    help="枚举DBMS模式")

        enumeration.add_argument("--count", dest="getCount", action="store_true",
                    help="检索表的条目数")

        enumeration.add_argument("--dump", dest="dumpTable", action="store_true",
                    help="转储DBMS数据库表条目")

        enumeration.add_argument("--dump-all", dest="dumpAll", action="store_true",
                    help="转储所有DBMS数据库表条目")

        enumeration.add_argument("--search", dest="search", action="store_true",
                    help="搜索列、表和/或数据库名称")

        enumeration.add_argument("--comments", dest="getComments", action="store_true",
                    help="在枚举过程中检查DBMS注释")

        enumeration.add_argument("--statements", dest="getStatements", action="store_true",
                    help="检索在DBMS上运行的SQL语句")

        enumeration.add_argument("-D", dest="db",
                    help="要枚举的DBMS数据库")

        enumeration.add_argument("-T", dest="tbl",
                    help="要枚举的DBMS数据库表")

        enumeration.add_argument("-C", dest="col",
                    help="要枚举的DBMS数据库表列")

        enumeration.add_argument("-X", dest="exclude",
                    help="不要枚举的DBMS数据库标识符")

        enumeration.add_argument("-U", dest="user",
                    help="要枚举的DBMS用户")

        enumeration.add_argument("--exclude-sysdbs", dest="excludeSysDbs", action="store_true",
                    help="在枚举表时排除DBMS系统数据库")

        enumeration.add_argument("--pivot-column", dest="pivotColumn",
                    help="枢轴列名称")

        enumeration.add_argument("--where", dest="dumpWhere",
                    help="在转储表时使用WHERE条件")

        enumeration.add_argument("--start", dest="limitStart", type=int,
                    help="要检索的第一个转储表条目")

        enumeration.add_argument("--stop", dest="limitStop", type=int,
                    help="要检索的最后一个转储表条目")

        enumeration.add_argument("--first", dest="firstChar", type=int,
                    help="要检索的第一个查询输出单词字符")

        enumeration.add_argument("--last", dest="lastChar", type=int,
                    help="要检索的最后一个查询输出单词字符")

        enumeration.add_argument("--sql-query", dest="sqlQuery",
                    help="要执行的SQL语句")

        enumeration.add_argument("--sql-shell", dest="sqlShell", action="store_true",
                    help="提示进行交互式SQL shell")

        enumeration.add_argument("--sql-file", dest="sqlFile",
                    help="从给定文件中执行SQL语句")

        # Brute force options
        brute = parser.add_argument_group("暴力破解", "这些选项可用于运行暴力破解检查")

        brute.add_argument("--common-tables", dest="commonTables", action="store_true",
                    help="检查常见表的存在")

        brute.add_argument("--common-columns", dest="commonColumns", action="store_true",
                    help="检查常见列的存在")

        brute.add_argument("--common-files", dest="commonFiles", action="store_true",
                    help="检查常见文件的存在")

        # User-defined function options
        udf = parser.add_argument_group("用户定义函数注入", "这些选项可用于创建自定义的用户定义函数")

        udf.add_argument("--udf-inject", dest="udfInject", action="store_true",
                    help="注入自定义的用户定义函数")

        udf.add_argument("--shared-lib", dest="shLib",
                    help="共享库的本地路径")

        # File system options
        filesystem = parser.add_argument_group("文件系统访问", "这些选项可用于访问后端数据库管理系统的底层文件系统")

        filesystem.add_argument("--file-read", dest="fileRead",
                    help="从后端DBMS文件系统中读取文件")

        filesystem.add_argument("--file-write", dest="fileWrite",
                    help="在后端DBMS文件系统上写入本地文件")

        filesystem.add_argument("--file-dest", dest="fileDest",
                    help="要写入的后端DBMS绝对文件路径")

        # Takeover options
        takeover = parser.add_argument_group("操作系统访问", "这些选项可用于访问后端数据库管理系统的底层操作系统")

        takeover.add_argument("--os-cmd", dest="osCmd",
                    help="执行操作系统命令")

        takeover.add_argument("--os-shell", dest="osShell", action="store_true",
                    help="提示进行交互式操作系统shell")

        takeover.add_argument("--os-pwn", dest="osPwn", action="store_true",
                    help="提示进行OOB shell、Meterpreter或VNC")

        takeover.add_argument("--os-smbrelay", dest="osSmb", action="store_true",
                    help="一键提示进行OOB shell、Meterpreter或VNC")

        takeover.add_argument("--os-bof", dest="osBof", action="store_true",
                    help="存储过程缓冲区溢出利用")

        takeover.add_argument("--priv-esc", dest="privEsc", action="store_true",
                    help="数据库进程用户权限提升")

        takeover.add_argument("--msf-path", dest="msfPath",
                    help="Metasploit Framework安装的本地路径")

        takeover.add_argument("--tmp-path", dest="tmpPath",
                    help="临时文件目录的远程绝对路径")

        # Windows registry options
        windows = parser.add_argument_group("Windows注册表访问", "这些选项可用于访问后端数据库管理系统的Windows注册表")

        windows.add_argument("--reg-read", dest="regRead", action="store_true",
                    help="读取Windows注册表键值")

        windows.add_argument("--reg-add", dest="regAdd", action="store_true",
                    help="写入Windows注册表键值数据")

        windows.add_argument("--reg-del", dest="regDel", action="store_true",
                    help="删除Windows注册表键值")

        windows.add_argument("--reg-key", dest="regKey",
                    help="Windows注册表键")

        windows.add_argument("--reg-value", dest="regVal",
                    help="Windows注册表键值")

        windows.add_argument("--reg-data", dest="regData",
                    help="Windows注册表键值数据")

        windows.add_argument("--reg-type", dest="regType",
                    help="Windows注册表键值类型")

        # General options
        general = parser.add_argument_group("常规", "这些选项可用于设置一些常规工作参数")

        general.add_argument("-s", dest="sessionFile",
                    help="从存储的(.sqlite)文件中加载会话")

        general.add_argument("-t", dest="trafficFile",
                    help="将所有HTTP流量记录到文本文件中")

        general.add_argument("--abort-on-empty", dest="abortOnEmpty", action="store_true",
                    help="在结果为空时中止数据检索")

        general.add_argument("--answers", dest="answers",
                    help="设置预定义的答案(例如\"quit=N,follow=N\")")

        general.add_argument("--base64", dest="base64Parameter",
                    help="包含Base64编码数据的参数")

        general.add_argument("--base64-safe", dest="base64Safe", action="store_true",
                    help="使用URL和文件名安全的Base64字母表(RFC 4648)")

        general.add_argument("--batch", dest="batch", action="store_true",
                    help="不要询问用户输入,使用默认行为")

        general.add_argument("--binary-fields", dest="binaryFields",
                    help="具有二进制值的结果字段(例如\"digest\")")

        general.add_argument("--check-internet", dest="checkInternet", action="store_true",
                    help="在评估目标之前检查互联网连接")

        general.add_argument("--cleanup", dest="cleanup", action="store_true",
                    help="从sqlmap特定的UDF和表中清理DBMS")

        general.add_argument("--crawl", dest="crawlDepth", type=int,
                    help="从目标URL开始爬取网站")

        general.add_argument("--crawl-exclude", dest="crawlExclude",
                    help="用于排除爬取的页面的正则表达式(例如\"logout\")")

        general.add_argument("--csv-del", dest="csvDel",
                    help="CSV输出中使用的分隔字符(默认值\"%s\")" % defaults.csvDel)

        general.add_argument("--charset", dest="charset",
                    help="盲SQL注入字符集(例如\"0123456789abcdef\")")

        general.add_argument("--dump-file", dest="dumpFile",
                    help="将转储的数据存储到自定义文件中")

        general.add_argument("--dump-format", dest="dumpFormat",
                    help="转储数据的格式(CSV(默认值),HTML或SQLITE)")

        general.add_argument("--encoding", dest="encoding",
                    help="用于数据检索的字符编码(例如GBK)")

        general.add_argument("--eta", dest="eta", action="store_true",
                    help="为每个输出显示预计到达时间")

        general.add_argument("--flush-session", dest="flushSession", action="store_true",
                    help="清除当前目标的会话文件")

        general.add_argument("--forms", dest="forms", action="store_true",
                    help="解析和测试目标URL上的表单")

        general.add_argument("--fresh-queries", dest="freshQueries", action="store_true",
                    help="忽略会话文件中存储的查询结果")

        general.add_argument("--gpage", dest="googlePage", type=int,
                    help="使用指定的页码从Google dork结果中获取")

        general.add_argument("--har", dest="harFile",
                    help="将所有HTTP流量记录到HAR文件中")

        general.add_argument("--hex", dest="hexConvert", action="store_true",
                    help="在数据检索过程中使用十六进制转换")

        general.add_argument("--output-dir", dest="outputDir", action="store",
                    help="自定义输出目录路径")

        general.add_argument("--parse-errors", dest="parseErrors", action="store_true",
                    help="解析和显示来自响应的DBMS错误消息")

        general.add_argument("--preprocess", dest="preprocess",
                    help="用于预处理的给定脚本(请求)")

        general.add_argument("--postprocess", dest="postprocess",
                    help="用于后处理的给定脚本(响应)")

        general.add_argument("--repair", dest="repair", action="store_true",
                    help="重新转储具有未知字符标记(%s)的条目" % INFERENCE_UNKNOWN_CHAR)

        general.add_argument("--save", dest="saveConfig",
                    help="将选项保存到配置INI文件中")

        general.add_argument("--scope", dest="scope",
                    help="用于过滤目标的正则表达式")

        general.add_argument("--skip-heuristics", dest="skipHeuristics", action="store_true",
                    help="跳过启发式检测漏洞")

        general.add_argument("--skip-waf", dest="skipWaf", action="store_true",
                    help="跳过启发式检测WAF/IPS保护")

        general.add_argument("--table-prefix", dest="tablePrefix",
                    help="用于临时表的前缀(默认值:\"%s\")" % defaults.tablePrefix)

        general.add_argument("--test-filter", dest="testFilter",
                    help="通过负载和/或标题选择测试(例如ROW)")

        general.add_argument("--test-skip", dest="testSkip",
                    help="通过负载和/或标题跳过测试(例如BENCHMARK)")

        general.add_argument("--time-limit", dest="timeLimit", type=float,
                    help="以秒为单位设置运行时间限制(例如3600)")

        general.add_argument("--web-root", dest="webRoot",
                    help="Web服务器文档根目录(例如\"/var/www\")")


        # Miscellaneous options
        miscellaneous = parser.add_argument_group("杂项", "这些选项不属于任何其他类别")

        miscellaneous.add_argument("-z", dest="mnemonics",
                    help="使用短助记符(例如\"flu,bat,ban,tec=EU\")")

        miscellaneous.add_argument("--alert", dest="alert",
                    help="在发现SQL注入时运行主机操作系统命令")

        miscellaneous.add_argument("--beep", dest="beep", action="store_true",
                    help="在提问交互时或发现漏洞时发出蜂鸣声")

        miscellaneous.add_argument("--dependencies", dest="dependencies", action="store_true",
                    help="检查缺失的(可选的)sqlmap依赖项")

        miscellaneous.add_argument("--disable-coloring", dest="disableColoring", action="store_true",
                    help="禁用控制台输出着色")

        miscellaneous.add_argument("--list-tampers", dest="listTampers", action="store_true",
                    help="显示可用的篡改脚本列表")

        miscellaneous.add_argument("--no-logging", dest="noLogging", action="store_true",
                    help="禁用日志记录到文件")

        miscellaneous.add_argument("--offline", dest="offline", action="store_true",
                    help="在离线模式下工作(仅使用会话数据)")

        miscellaneous.add_argument("--purge", dest="purge", action="store_true",
                    help="安全地从sqlmap数据目录中删除所有内容")

        miscellaneous.add_argument("--results-file", dest="resultsFile",
                    help="多目标模式下CSV结果文件的位置")

        miscellaneous.add_argument("--shell", dest="shell", action="store_true",
                    help="提示进行交互式sqlmap shell")

        miscellaneous.add_argument("--tmp-dir", dest="tmpDir",
                    help="用于存储临时文件的本地目录")

        miscellaneous.add_argument("--unstable", dest="unstable", action="store_true",
                    help="调整不稳定连接的选项")

        miscellaneous.add_argument("--update", dest="updateAll", action="store_true",
                    help="更新sqlmap")

        miscellaneous.add_argument("--wizard", dest="wizard", action="store_true",
                    help="面向初学者用户的简单向导界面")

        # Hidden and/or experimental options
        parser.add_argument("--crack", dest="hashFile",
            help=SUPPRESS)  # "Load and crack hashes from a file (standalone)"

        parser.add_argument("--dummy", dest="dummy", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--yuge", dest="yuge", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--murphy-rate", dest="murphyRate", type=int,
            help=SUPPRESS)

        parser.add_argument("--debug", dest="debug", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--deprecations", dest="deprecations", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-multi", dest="disableMulti", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-precon", dest="disablePrecon", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-stats", dest="disableStats", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--profile", dest="profile", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--localhost", dest="localhost", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-dbms", dest="forceDbms",
            help=SUPPRESS)

        parser.add_argument("--force-dns", dest="forceDns", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-partial", dest="forcePartial", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--force-pivoting", dest="forcePivoting", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--ignore-stdin", dest="ignoreStdin", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--non-interactive", dest="nonInteractive", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--gui", dest="gui", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--smoke-test", dest="smokeTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--vuln-test", dest="vulnTest", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--disable-json", dest="disableJson", action="store_true",
            help=SUPPRESS)

        # API options
        parser.add_argument("--api", dest="api", action="store_true",
            help=SUPPRESS)

        parser.add_argument("--taskid", dest="taskid",
            help=SUPPRESS)

        parser.add_argument("--database", dest="database",
            help=SUPPRESS)

        # Dirty hack to display longer options without breaking into two lines
        if hasattr(parser, "formatter"):
            def _(self, *args):
                retVal = parser.formatter._format_option_strings(*args)
                if len(retVal) > MAX_HELP_OPTION_LENGTH:
                    retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retVal
                return retVal

            parser.formatter._format_option_strings = parser.formatter.format_option_strings
            parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser)
        else:
            def _format_action_invocation(self, action):
                retVal = self.__format_action_invocation(action)
                if len(retVal) > MAX_HELP_OPTION_LENGTH:
                    retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - self._indent_increment)) % retVal
                return retVal

            parser.formatter_class.__format_action_invocation = parser.formatter_class._format_action_invocation
            parser.formatter_class._format_action_invocation = _format_action_invocation

        # Dirty hack for making a short option '-hh'
        if hasattr(parser, "get_option"):
            option = parser.get_option("--hh")
            option._short_opts = ["-hh"]
            option._long_opts = []
        else:
            for action in get_actions(parser):
                if action.option_strings == ["--hh"]:
                    action.option_strings = ["-hh"]
                    break

        # Dirty hack for inherent help message of switch '-h'
        if hasattr(parser, "get_option"):
            option = parser.get_option("-h")
            option.help = option.help.capitalize().replace("this help", "basic help")
        else:
            for action in get_actions(parser):
                if action.option_strings == ["-h", "--help"]:
                    action.help = action.help.capitalize().replace("this help", "basic help")
                    break

        _ = []
        advancedHelp = True
        extraHeaders = []
        auxIndexes = {}

        # Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
        for arg in argv:
            _.append(getUnicode(arg, encoding=sys.stdin.encoding))

        argv = _
        checkOldOptions(argv)

        if "--gui" in argv:
            from lib.core.gui import runGui

            runGui(parser)

            raise SqlmapSilentQuitException

        elif "--shell" in argv:
            _createHomeDirectories()

            parser.usage = ""
            cmdLineOptions.sqlmapShell = True

            commands = set(("x", "q", "exit", "quit", "clear"))
            commands.update(get_all_options(parser))

            autoCompletion(AUTOCOMPLETE_TYPE.SQLMAP, commands=commands)

            while True:
                command = None
                prompt = "sqlmap > "

                try:
                    # Note: in Python2 command should not be converted to Unicode before passing to shlex (Reference: https://bugs.python.org/issue1170)
                    command = _input(prompt).strip()
                except (KeyboardInterrupt, EOFError):
                    print()
                    raise SqlmapShellQuitException

                command = re.sub(r"(?i)\Anew\s+", "", command or "")

                if not command:
                    continue
                elif command.lower() == "clear":
                    clearHistory()
                    dataToStdout("[i] history cleared\n")
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                elif command.lower() in ("x", "q", "exit", "quit"):
                    raise SqlmapShellQuitException
                elif command[0] != '-':
                    if not re.search(r"(?i)\A(\?|help)\Z", command):
                        dataToStdout("[!] invalid option(s) provided\n")
                    dataToStdout("[i] valid example: '-u http://www.site.com/vuln.php?id=1 --banner'\n")
                else:
                    saveHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    loadHistory(AUTOCOMPLETE_TYPE.SQLMAP)
                    break

            try:
                for arg in shlex.split(command):
                    argv.append(getUnicode(arg, encoding=sys.stdin.encoding))
            except ValueError as ex:
                raise SqlmapSyntaxException("something went wrong during command line parsing ('%s')" % getSafeExString(ex))

        longOptions = set(re.findall(r"\-\-([^= ]+?)=", parser.format_help()))
        longSwitches = set(re.findall(r"\-\-([^= ]+?)\s", parser.format_help()))

        for i in xrange(len(argv)):
            # Reference: https://en.wiktionary.org/wiki/-
            argv[i] = re.sub(u"\\A(\u2010|\u2013|\u2212|\u2014|\u4e00|\u1680|\uFE63|\uFF0D)+", lambda match: '-' * len(match.group(0)), argv[i])

            # Reference: https://unicode-table.com/en/sets/quotation-marks/
            argv[i] = argv[i].strip(u"\u00AB\u2039\u00BB\u203A\u201E\u201C\u201F\u201D\u2019\u275D\u275E\u276E\u276F\u2E42\u301D\u301E\u301F\uFF02\u201A\u2018\u201B\u275B\u275C")

            if argv[i] == "-hh":
                argv[i] = "-h"
            elif i == 1 and re.search(r"\A(http|www\.|\w[\w.-]+\.\w{2,})", argv[i]) is not None:
                argv[i] = "--url=%s" % argv[i]
            elif len(argv[i]) > 1 and all(ord(_) in xrange(0x2018, 0x2020) for _ in ((argv[i].split('=', 1)[-1].strip() or ' ')[0], argv[i][-1])):
                dataToStdout("[!] copy-pasting illegal (non-console) quote characters from Internet is illegal (%s)\n" % argv[i])
                raise SystemExit
            elif len(argv[i]) > 1 and u"\uff0c" in argv[i].split('=', 1)[-1]:
                dataToStdout("[!] copy-pasting illegal (non-console) comma characters from Internet is illegal (%s)\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w=.+", argv[i]):
                dataToStdout("[!] potentially miswritten (illegal '=') short option detected ('%s')\n" % argv[i])
                raise SystemExit
            elif re.search(r"\A-\w{3,}", argv[i]):
                if argv[i].strip('-').split('=')[0] in (longOptions | longSwitches):
                    argv[i] = "-%s" % argv[i]
            elif argv[i] in IGNORED_OPTIONS:
                argv[i] = ""
            elif argv[i] in DEPRECATED_OPTIONS:
                argv[i] = ""
            elif argv[i].startswith("--data-raw"):
                argv[i] = argv[i].replace("--data-raw", "--data", 1)
            elif argv[i].startswith("--auth-creds"):
                argv[i] = argv[i].replace("--auth-creds", "--auth-cred", 1)
            elif argv[i].startswith("--drop-cookie"):
                argv[i] = argv[i].replace("--drop-cookie", "--drop-set-cookie", 1)
            elif re.search(r"\A--tamper[^=\s]", argv[i]):
                argv[i] = ""
                continue
            elif re.search(r"\A(--(tamper|ignore-code|skip))(?!-)", argv[i]):
                key = re.search(r"\-?\-(\w+)\b", argv[i]).group(1)
                index = auxIndexes.get(key, None)
                if index is None:
                    index = i if '=' in argv[i] else (i + 1 if i + 1 < len(argv) and not argv[i + 1].startswith('-') else None)
                    auxIndexes[key] = index
                else:
                    delimiter = ','
                    argv[index] = "%s%s%s" % (argv[index], delimiter, argv[i].split('=')[1] if '=' in argv[i] else (argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith('-') else ""))
                    argv[i] = ""
            elif argv[i] in ("-H", "--header") or any(argv[i].startswith("%s=" % _) for _ in ("-H", "--header")):
                if '=' in argv[i]:
                    extraHeaders.append(argv[i].split('=', 1)[1])
                elif i + 1 < len(argv):
                    extraHeaders.append(argv[i + 1])
            elif argv[i] == "--deps":
                argv[i] = "--dependencies"
            elif argv[i] == "--disable-colouring":
                argv[i] = "--disable-coloring"
            elif argv[i] == "-r":
                for j in xrange(i + 2, len(argv)):
                    value = argv[j]
                    if os.path.isfile(value):
                        argv[i + 1] += ",%s" % value
                        argv[j] = ''
                    else:
                        break
            elif re.match(r"\A\d+!\Z", argv[i]) and argv[max(0, i - 1)] == "--threads" or re.match(r"\A--threads.+\d+!\Z", argv[i]):
                argv[i] = argv[i][:-1]
                conf.skipThreadCheck = True
            elif argv[i] == "--version":
                print(VERSION_STRING.split('/')[-1])
                raise SystemExit
            elif argv[i] in ("-h", "--help"):
                advancedHelp = False
                for group in get_groups(parser)[:]:
                    found = False
                    for option in get_actions(group):
                        if option.dest not in BASIC_HELP_ITEMS:
                            option.help = SUPPRESS
                        else:
                            found = True
                    if not found:
                        get_groups(parser).remove(group)
            elif '=' in argv[i] and not argv[i].startswith('-') and argv[i].split('=')[0] in longOptions and re.search(r"\A-{1,2}\w", argv[i - 1]) is None:
                dataToStdout("[!] detected usage of long-option without a starting hyphen ('%s')\n" % argv[i])
                raise SystemExit

        for verbosity in (_ for _ in argv if re.search(r"\A\-v+\Z", _)):
            try:
                if argv.index(verbosity) == len(argv) - 1 or not argv[argv.index(verbosity) + 1].isdigit():
                    conf.verbose = verbosity.count('v')
                    del argv[argv.index(verbosity)]
            except (IndexError, ValueError):
                pass

        try:
            (args, _) = parser.parse_known_args(argv) if hasattr(parser, "parse_known_args") else parser.parse_args(argv)
        except UnicodeEncodeError as ex:
            dataToStdout("\n[!] %s\n" % getUnicode(ex.object.encode("unicode-escape")))
            raise SystemExit
        except SystemExit:
            if "-h" in argv and not advancedHelp:
                dataToStdout("\n[!] 查看选项的完整列表 '-hh'\n")
            raise

        if extraHeaders:
            if not args.headers:
                args.headers = ""
            delimiter = "\\n" if "\\n" in args.headers else "\n"
            args.headers += delimiter + delimiter.join(extraHeaders)

        # Expand given mnemonic options (e.g. -z "ign,flu,bat")
        for i in xrange(len(argv) - 1):
            if argv[i] == "-z":
                expandMnemonics(argv[i + 1], parser, args)

        if args.dummy:
            args.url = args.url or DUMMY_URL

        if hasattr(sys.stdin, "fileno") and not any((os.isatty(sys.stdin.fileno()), args.api, args.ignoreStdin, "GITHUB_ACTIONS" in os.environ)):
            args.stdinPipe = iter(sys.stdin.readline, None)
        else:
            args.stdinPipe = None

        if not any((args.direct, args.url, args.logFile, args.bulkFile, args.googleDork, args.configFile, args.requestFile, args.updateAll, args.smokeTest, args.vulnTest, args.wizard, args.dependencies, args.purge, args.listTampers, args.hashFile, args.stdinPipe)):
            errMsg = "缺少强制选项 (-d, -u, -l, -m, -r, -g, -c, --wizard, --shell, --update, --purge, --list-tampers or --dependencies). "
            errMsg += "使用 -h 表示基本帮助,使用 -hh 表示高级帮助\n"
            parser.error(errMsg)

        return args

    except (ArgumentError, TypeError) as ex:
        parser.error(ex)

    except SystemExit:
        # Protection against Windows dummy double clicking
        if IS_WIN and "--non-interactive" not in sys.argv:
            dataToStdout("\n按Enter键继续...")
            _input()
        raise

    debugMsg = "解析命令行参数"
    logger.debug(debugMsg)
