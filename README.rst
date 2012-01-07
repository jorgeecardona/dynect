Dynect API Wrapper
==================

Library to ease the usage of Dynect API. Following the supports document in https://manage.dynect.net/help/docs/api2/quickstart/ the library will expose a componetn to login to dynect, create changes and publish them.

Installation
------------

For now use this repo::

    pip install -e git+git@github.com:jorgeecardona/dynect.git#egg=dynect


Usage
-----

Start a session::

    from dynect import Dynect
    dyn = Dynect('customer_name', 'username', 'password', 'www.test.com')
    
    # Create a new address.
    record = dyn.add_address('www.test.com', '1.1.1.1')
    assert record.address = '1.1.1.1'
    assert record.fqdn = 'www.test.com'
    
    # Delete the address.
    record.delete()
