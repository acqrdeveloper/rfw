#!/usr/bin/env python
#
# Copyrite (c) 2018 Alok G Singh
#
# This file is part of rfw
#
# The MIT License (MIT)
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
import requests

class Client(object):
    def __init__(self, base_url, auth):
        self.base_url = base_url
        self.auth = requests.auth.HTTPBasicAuth(auth[0], auth[1])
        
    def _parse_response(self, r):
        if r.status_code != 200:
            raise Exception("Error in request to server: {}".format(r.text))

        return r.text
    
    def _put(self, obj, url):
        return self._parse_response(requests.put(url, data=obj.to_json(), auth=self.auth))

    def _delete(self, obj, url):
        return self._parse_response(requests.delete(url, data=obj.to_json(), auth=self.auth))

    def _get(self, obj, url):
        return self._parse_response(requests.get(url, auth=self.auth))

    def add_rule(self, r):
        self._put(r, '{burl}/rule'.format(burl=self.base_url))

    def del_rule(self, r):
        self._delete(r, '{burl}/rule'.format(burl=self.base_url))

    def add_chain(self, c):
        self._put(c, '{burl}/chain/{chain}'.format(burl=self.base_url,
                                                   chain=c.name))

    def del_chain(self, c):
        self._delete(c, '{burl}/chain/{chain}'.format(burl=self.base_url,
                                                      chain=c.name))

    def list_chain(self, c):
        r = self._get(c, '{burl}/list/{chain}'.format(burl=self.base_url,
                                                      chain=c.name))
        print(r)
