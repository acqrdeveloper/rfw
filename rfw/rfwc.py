#!/usr/bin/env python
#
# Copyrite (c) 2014 SecurityKISS Ltd (http://www.securitykiss.com)
# (c) 2018 Alok G Singh
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

from __future__ import print_function
import argparse, pkg_resources, os
import client, iptables

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="subcommand")

def subcommand(args=[], parent=subparsers):
    """Decorator to add to functions.
    See https://mike.depalatis.net/blog/simplifying-argparse.html
    """
    def decorator(func):
        parser = parent.add_parser(func.__name__, description=func.__doc__)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)
    return decorator

def argument(*name_or_flags, **kwargs):
    """Helper function to satisfy argparse.ArgumentParser.add_argument()'s
    input argument syntax"""
    return (list(name_or_flags), kwargs)

def auth_from_env(user, passwd):
    return (user or os.environ.get('RFW_USER'),
            passwd or os.environ.get('RFW_PASS'))


@subcommand([argument('op', help="Operation to perform.", choices=['add','rm']),
             argument('chain', help="Chain the rule will be inserted into"),
             argument('target', help="Target of the rule: DROP, REJECT, etc."),
             argument('-p', '--proto', help="Protocol to use. Default is all.", dest='prot', default='tcp'),
             argument('-d', '--dport', help="Destination port"),
             argument('-s', '--sport', help="Source port"),
             argument('-i', '--input', help="Input interface", dest='inp', default='*'),
             argument('-o', '--output', help="Output interface", dest='out', default='*'),
             argument('-sn', '--source', help="Source network", default='0.0.0.0/0'),
             argument('-dn', '--dest', help="Destination network", dest='destination', default='0.0.0.0/0')])
def rule(args, c):
    """Take just the bits needed to create a rule from the args object
    """
    # Gets the __dict__ inside args
    d = vars(args)
    # Just take the bits we need from args to construct a Rule object
    r0 = { k: d[k] for k in d if k in iptables.RULE_FIELDS }
    r = iptables.Rule(r0)
    print(r)
    if args.op.upper() == 'ADD':
        c.add_rule(r)
    else:
        c.del_rule(r)

@subcommand([argument('op', help="Operation to perform.", choices=['add','rm','list']),
             argument('name', help="Chain name")])
def chain(args, c):
    ch = iptables.Chain(args.name)
    if args.op.upper() == 'ADD':
        c.add_chain(ch)
    elif args.op.upper() == 'RM':
        c.del_chain(ch)
    else:
        c.list_chain(ch)
        
#
# Start here

if __name__ == '__main__':
    # Try to obtain version
    __version__ = '0.0.0'
    try:
        __version__ = pkg_resources.require("rfw")[0].version
    except pkg_resources.DistributionNotFound:
        v_file = os.path.join(os.path.dirname(__file__), '_version.py')
        if os.path.isfile(v_file):
            execfile(os.path.join(os.path.dirname(__file__), '_version.py'))

    parser.add_argument('-v', '--version', action='version', version=__version__)
    parser.add_argument('-d', '--debug', action='store_true', help='Show API traces')
    parser.add_argument('-u', '--url', help='API endpoint. Uses environment variable RFW_API_URL if defined', default='http://localhost:7390')
    parser.add_argument('--user', help='Username for authentication. Uses environment variable RFW_USER if defined')
    parser.add_argument('--passwd', help='Password for authentication. Uses environment variable RFW_PASS if defined')

    args = parser.parse_args()
    if args.subcommand is None:
        parser.print_help()
    else:
        auth = auth_from_env(args.user, args.passwd)
        c = client.Client(args.url, auth)
        args.func(args, c)
