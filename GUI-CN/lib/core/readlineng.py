#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

_readline = None
try:
    from readline import *
    import readline as _readline
except:
    try:
        from pyreadline import *
        import pyreadline as _readline
    except:
        pass

from lib.core.data import logger
from lib.core.settings import IS_WIN
from lib.core.settings import PLATFORM

if IS_WIN and _readline:
    try:
        _outputfile = _readline.GetOutputFile()
    except AttributeError:
        debugMsg = "使用平台的 readline 库时获取输出文件失败"
        logger.debug(debugMsg)

        _readline = None

# Test to see if libedit is being used instead of GNU readline.
# Thanks to Boyd Waters for this patch.
uses_libedit = False

if PLATFORM == "mac" and _readline:
    import commands

    (status, result) = commands.getstatusoutput("otool -L %s | grep libedit" % _readline.__file__)

    if status == 0 and len(result) > 0:
        # We are bound to libedit - new in Leopard
        _readline.parse_and_bind("bind ^I rl_complete")

        debugMsg = "检测到 Leopard libedit 当使用平台的 readline 库时"
        logger.debug(debugMsg)

        uses_libedit = True

# the clear_history() function was only introduced in Python 2.4 and is
# actually optional in the readline API, so we must explicitly check for its
# existence.  Some known platforms actually don't have it.  This thread:
# http://mail.python.org/pipermail/python-dev/2003-August/037845.html
# has the original discussion.
if _readline:
    if not hasattr(_readline, "clear_history"):
        def clear_history():
            pass

        _readline.clear_history = clear_history
