.. Dynect documentation master file, created by
   sphinx-quickstart on Sat Jan  7 18:16:09 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

==================================
Welcome to Dynect's documentation!
==================================

:Date: |today|

.. toctree::
   :maxdepth: 2

   api
   license


Overview
========

``dynect`` is a library to use the Dyn API to manage the DNS Lite service.

Features
--------

- Easy to use.
- Pool connection thanks to ``urllib3`` and ``requests``.

Installation
============

To install the last version use ``pip``::

  pip install dynect

Example
=======

You can use it to create a new record::

  from dynect import Dynect
  dyn = Dynect('customer', 'username', 'password', 'zone.com')
  record = dyn.add_address('www.zone.com', '1.1.1.1')
  dyn.publish()

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

