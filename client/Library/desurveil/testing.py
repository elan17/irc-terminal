#!/usr/bin/env python3

# desurveil: a cryptography tool with support for RSA and OAEP
# Copyright (C) 2011 Niels Serup

# This file is part of desurveil.
#
# desurveil is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# desurveil is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with desurveil.  If not, see <http://www.gnu.org/licenses/>.

"""
This module contains code to help speed test functions etc.
"""

import datetime

def time_exec(func, orig_ret=False):
    """
    time_exec(func : function, orig_ret : bool = False) ->
    milliseconds : int[, func return value]

    Measure how long it takes to run func. If orig_ret, return both time and
    return value from func.
    """
    t = datetime.datetime.now()
    r = func()
    t = datetime.datetime.now() - t
    t = ((t.days * 24 * 60 * 60 + t.seconds) *
         1000000 + t.microseconds) / 1000
    if orig_ret:
        return t, r
    else:
        return t
