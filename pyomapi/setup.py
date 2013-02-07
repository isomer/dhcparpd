#!/usr/bin/env python

from distutils.core import setup,Extension

module1 = Extension('_omapi',
        sources = ['omapi_wrap.c', 'base64.c'],
        include_dirs = ['/include/'],
        libraries = ['dhcpctl', 'omapi', 'dst'])

setup(name="omapi",
        version="1.0",
        description="Python OMAPI (DHCP) Interface",
        author="Perry Lorier, Matt Brown",
        author_email="perry@coders.net,matt@mattb.net.nz",
        url="http://source.meta.net.nz/svn/dhcparpd/trunk/pyomapi/",
        ext_modules=[module1],
        py_modules=['omapi'],
        )
