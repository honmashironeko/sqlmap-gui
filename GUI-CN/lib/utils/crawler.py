#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import os
import re
import tempfile
import time

from lib.core.common import checkSameHost
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import findPageForms
from lib.core.common import getSafeExString
from lib.core.common import openFile
from lib.core.common import readInput
from lib.core.common import safeCSValue
from lib.core.common import urldecode
from lib.core.compat import xrange
from lib.core.convert import htmlUnescape
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import OrderedSet
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapSyntaxException
from lib.core.settings import CRAWL_EXCLUDE_EXTENSIONS
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.parse.sitemap import parseSitemap
from lib.request.connect import Connect as Request
from thirdparty import six
from thirdparty.beautifulsoup.beautifulsoup import BeautifulSoup
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import urllib as _urllib

def crawl(target, post=None, cookie=None):
    if not target:
        return

    try:
        visited = set()
        threadData = getCurrentThreadData()
        threadData.shared.value = OrderedSet()
        threadData.shared.formsFound = False

        def crawlThread():
            threadData = getCurrentThreadData()

            while kb.threadContinue:
                with kb.locks.limit:
                    if threadData.shared.unprocessed:
                        current = threadData.shared.unprocessed.pop()
                        if current in visited:
                            continue
                        elif conf.crawlExclude and re.search(conf.crawlExclude, current):
                            dbgMsg = "跳过 '%s'" % current
                            logger.debug(dbgMsg)
                            continue
                        else:
                            visited.add(current)
                    else:
                        break

                content = None
                try:
                    if current:
                        content = Request.getPage(url=current, post=post, cookie=None, crawling=True, raise404=False)[0]
                except SqlmapConnectionException as ex:
                    errMsg = "检测到连接异常('%s')。跳过URL '%s'" % (getSafeExString(ex), current)
                    logger.critical(errMsg)
                except SqlmapSyntaxException:
                    errMsg = "检测到无效的URL。跳过 '%s'" % current
                    logger.critical(errMsg)
                except _http_client.InvalidURL as ex:
                    errMsg = "检测到无效的URL('%s')。跳过URL '%s'" % (getSafeExString(ex), current)
                    logger.critical(errMsg)

                if not kb.threadContinue:
                    break

                if isinstance(content, six.text_type):
                    try:
                        match = re.search(r"(?si)<html[^>]*>(.+)</html>", content)
                        if match:
                            content = "<html>%s</html>" % match.group(1)

                        soup = BeautifulSoup(content)
                        tags = soup('a')

                        tags += re.finditer(r'(?i)\s(href|src)=["\'](?P<href>[^>"\']+)', content)
                        tags += re.finditer(r'(?i)window\.open\(["\'](?P<href>[^)"\']+)["\']', content)

                        for tag in tags:
                            href = tag.get("href") if hasattr(tag, "get") else tag.group("href")

                            if href:
                                if threadData.lastRedirectURL and threadData.lastRedirectURL[0] == threadData.lastRequestUID:
                                    current = threadData.lastRedirectURL[1]
                                url = _urllib.parse.urljoin(current, htmlUnescape(href))

                                # flag to know if we are dealing with the same target host
                                _ = checkSameHost(url, target)

                                if conf.scope:
                                    if not re.search(conf.scope, url, re.I):
                                        continue
                                elif not _:
                                    continue

                                if (extractRegexResult(r"\A[^?]+\.(?P<result>\w+)(\?|\Z)", url) or "").lower() not in CRAWL_EXCLUDE_EXTENSIONS:
                                    with kb.locks.value:
                                        threadData.shared.deeper.add(url)
                                        if re.search(r"(.*?)\?(.+)", url) and not re.search(r"\?(v=)?\d+\Z", url) and not re.search(r"(?i)\.(js|css)(\?|\Z)", url):
                                            threadData.shared.value.add(url)
                    except UnicodeEncodeError:  # for non-HTML files
                        pass
                    except ValueError:          # for non-valid links
                        pass
                    except AssertionError:      # for invalid HTML
                        pass
                    finally:
                        if conf.forms:
                            threadData.shared.formsFound |= len(findPageForms(content, current, False, True)) > 0

                if conf.verbose in (1, 2):
                    threadData.shared.count += 1
                    status = '%d/%d links visited (%d%%)' % (threadData.shared.count, threadData.shared.length, round(100.0 * threadData.shared.count / threadData.shared.length))
                    dataToStdout("\r[%s] [INFO] %s" % (time.strftime("%X"), status), True)

        threadData.shared.deeper = set()
        threadData.shared.unprocessed = set([target])

        _ = re.sub(r"(?<!/)/(?!/).*", "", target)
        if _:
            if target.strip('/') != _.strip('/'):
                threadData.shared.unprocessed.add(_)

        if re.search(r"\?.*\b\w+=", target):
            threadData.shared.value.add(target)

        if kb.checkSitemap is None:
            message = "你想要检查站点是否存在网站地图(.xml)吗？[y/N] "
            kb.checkSitemap = readInput(message, default='N', boolean=True)

        if kb.checkSitemap:
            found = True
            items = None
            url = _urllib.parse.urljoin(target, "/sitemap.xml")
            try:
                items = parseSitemap(url)
            except SqlmapConnectionException as ex:
                if "page not found" in getSafeExString(ex):
                    found = False
                    logger.warning("未找到 'sitemap.xml'")
            except:
                pass
            finally:
                if found:
                    if items:
                        for item in items:
                            if re.search(r"(.*?)\?(.+)", item):
                                threadData.shared.value.add(item)
                        if conf.crawlDepth > 1:
                            threadData.shared.unprocessed.update(items)
                    logger.info("%s个链接已找到" % ("没有" if not items else len(items)))

        if not conf.bulkFile:
            infoMsg = "启动目标URL '%s' 的爬虫" % target
            logger.info(infoMsg)

        for i in xrange(conf.crawlDepth):
            threadData.shared.count = 0
            threadData.shared.length = len(threadData.shared.unprocessed)
            numThreads = min(conf.threads, len(threadData.shared.unprocessed))

            if not conf.bulkFile:
                logger.info("搜索深度为 %d 的链接" % (i + 1))

            runThreads(numThreads, crawlThread, threadChoice=(i > 0))
            clearConsoleLine(True)

            if threadData.shared.deeper:
                threadData.shared.unprocessed = set(threadData.shared.deeper)
            else:
                break

    except KeyboardInterrupt:
        warnMsg = "用户在爬取过程中中止。sqlmap将使用部分列表"
        logger.warning(warnMsg)

    finally:
        clearConsoleLine(True)

        if not threadData.shared.value:
            if not (conf.forms and threadData.shared.formsFound):
                warnMsg = "未找到可用的链接(带有GET参数)"
                if conf.forms:
                    warnMsg += "或表单"
                logger.warning(warnMsg)
        else:
            for url in threadData.shared.value:
                kb.targets.add((urldecode(url, kb.pageEncoding), None, None, None, None))

        if kb.targets:
            if kb.normalizeCrawlingChoice is None:
                message = "您是否要规范化爬取结果 [Y/n] "

                kb.normalizeCrawlingChoice = readInput(message, default='Y', boolean=True)

            if kb.normalizeCrawlingChoice:
                seen = set()
                results = OrderedSet()

                for target in kb.targets:
                    value = "%s%s%s" % (target[0], '&' if '?' in target[0] else '?', target[2] or "")
                    match = re.search(r"/[^/?]*\?.+\Z", value)
                    if match:
                        key = re.sub(r"=[^=&]*", "=", match.group(0)).strip("&?")
                        if '=' in key and key not in seen:
                            results.add(target)
                            seen.add(key)

                kb.targets = results

            storeResultsToFile(kb.targets)

def storeResultsToFile(results):
    if not results:
        return

    if kb.storeCrawlingChoice is None:
        message = "您是否要将爬取结果存储到临时文件中,以便以后使用其他工具进行进一步处理 [y/N] "

        kb.storeCrawlingChoice = readInput(message, default='N', boolean=True)

    if kb.storeCrawlingChoice:
        handle, filename = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.CRAWLER, suffix=".csv" if conf.forms else ".txt")
        os.close(handle)

        infoMsg = "将爬取结果写入临时文件 '%s'" % filename
        logger.info(infoMsg)

        with openFile(filename, "w+b") as f:
            if conf.forms:
                f.write("URL,POST\n")

            for url, _, data, _, _ in results:
                if conf.forms:
                    f.write("%s,%s\n" % (safeCSValue(url), safeCSValue(data or "")))
                else:
                    f.write("%s\n" % url)
