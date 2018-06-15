#!/usr/bin/env python
#
# Copyrite (c) 2014 SecurityKISS Ltd (http://www.securitykiss.com)  
#
# This file is part of rfw
#
# The MIT License (MIT)
#
# Yes, Mr patent attorney, you have nothing to do here. Find a decent job instead. 
# Fight intellectual "property".
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import sys, logging, urlparse, re, json
import iputil, timeutil, iptables
from iptables import Rule, Chain

log = logging.getLogger("rfw.cmdparse")


class PathError(Exception):
    def __init__(self, path, msg=''):
        Exception.__init__(self, 'Incorrect path: {}. {}'.format(path, msg))


# return tuple:
# '/' -> tuple()
# '/list' -> ('list', '')
# '/list/input' -> ('list', 'input')
# '/drop/input/eth0/1.2.3.4' -> ('drop', Rule(...))

def parse_command_path(path, body):
    # split url path into parts, lowercase, trim trailing slash, return tuple
    def path_parts(path):
        path = path.strip().lower()
        if len(path) < 1 or path[0] != '/':
            raise PathError(path)
        if path[-1] == '/':
            path = path[:-1]
        p = map(str.strip, path.split('/'))
        p = tuple(p[1:])
        return p

    p = path_parts(path)

    # for path = '/' return 'help' action
    if not p:
        return 'help', None

    action = p[0]

    try:
        if action.upper() == 'RULE':
            return action, build_rule(body)
        elif action.upper() == 'CHAIN':
            return action, build_chain(p[1], body)
    except ValueError, e:
        raise PathError(path, e.message)
    except IndexError:
        raise PathError(path, "Missing chain name")
    
    if action == 'list':
        if len(p) == 1:
            return action, None
        elif len(p) == 2:
            chain = p[1]
            return action, chain
        else:
            raise PathError(path, 'Too many details for the list command')
        
    raise PathError(path)


# From the path parts tuple build and return Rule for drop/accept/reject type of command
def build_rule(params):

    p = json.loads(params)

    return Rule(p)


def build_chain(chain, params):
    return Chain(chain)

def parse_command_query(query):
    params = dict(urlparse.parse_qsl(query))
    ret = {}
    
    expire = params.get('expire')
    if expire:
        interval = timeutil.parse_interval(expire)
        if interval is None:
            raise ValueError('Incorrect expire parameter value')
        ret['expire'] = str(interval)

    wait = params.get('wait')
    if wait:
        wait = wait.lower()
        if wait == 'true':
            ret['wait'] = wait
        else:
            raise ValueError('Incorrect wait parameter value')


    modify = params.get('modify')
    if modify:
        modify = modify.lower()
        if modify in ['insert', 'delete']:
            ret['modify'] = modify
        else:
            raise ValueError('Incorrect modify parameter value')
    return ret



def parse_command(url, body):
    """
    return dict with command elements like:
    {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'expire': '3600'}
    """
    # split input to path and query
    # path specifies the iptables Rule while query provides additional rfw parameters like expire or wait
    parsed = urlparse.urlparse(url)
    path, query = parsed.path, parsed.query

    action, rule = parse_command_path(path, body)
    directives = parse_command_query(query)

    return (action, rule, directives) 


