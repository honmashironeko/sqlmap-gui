#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import functools
import os
import random
import shutil
import stat
import string

from lib.core.common import getSafeExString
from lib.core.common import openFile
from lib.core.compat import xrange
from lib.core.convert import getUnicode
from lib.core.data import logger
from thirdparty.six import unichr as _unichr

def purge(directory):
    """
    Safely removes content from a given directory
    """

    if not os.path.isdir(directory):
        warnMsg = "跳过清理目录 '%s',因为它不存在" % directory
        logger.warning(warnMsg)
        return

    infoMsg = "清理目录 '%s' 的内容..." % directory
    logger.info(infoMsg)

    filepaths = []
    dirpaths = []

    for rootpath, directories, filenames in os.walk(directory):
        dirpaths.extend(os.path.abspath(os.path.join(rootpath, _)) for _ in directories)
        filepaths.extend(os.path.abspath(os.path.join(rootpath, _)) for _ in filenames)

    logger.debug("正在更改文件属性")
    for filepath in filepaths:
        try:
            os.chmod(filepath, stat.S_IREAD | stat.S_IWRITE)
        except:
            pass

    logger.debug("向文件写入随机数据")
    for filepath in filepaths:
        try:
            filesize = os.path.getsize(filepath)
            with openFile(filepath, "w+b") as f:
                f.write("".join(_unichr(random.randint(0, 255)) for _ in xrange(filesize)))
        except:
            pass

    logger.debug("正在截断文件")
    for filepath in filepaths:
        try:
            with open(filepath, 'w') as f:
                pass
        except:
            pass

    logger.debug("将文件名重命名为随机值")
    for filepath in filepaths:
        try:
            os.rename(filepath, os.path.join(os.path.dirname(filepath), "".join(random.sample(string.ascii_letters, random.randint(4, 8)))))
        except:
            pass

    dirpaths.sort(key=functools.cmp_to_key(lambda x, y: y.count(os.path.sep) - x.count(os.path.sep)))

    logger.debug("将目录名重命名为随机值")
    for dirpath in dirpaths:
        try:
            os.rename(dirpath, os.path.join(os.path.dirname(dirpath), "".join(random.sample(string.ascii_letters, random.randint(4, 8)))))
        except:
            pass

    logger.debug("删除整个目录树")
    try:
        shutil.rmtree(directory)
    except OSError as ex:
        logger.error("删除目录 '%s' 时发生问题('%s')" % (getUnicode(directory), getSafeExString(ex)))
