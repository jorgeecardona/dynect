import logging

from requests.packages.urllib3.connectionpool import HTTPSConnectionPool
from requests.packages.urllib3 import HTTPResponse
from unittest import TestCase
from mock import patch
from StringIO import StringIO

from dynect import Dynect

_Default = object()


log = logging.getLogger('DynectTestCase')
log.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    '%(asctime)s:%(levelname)s:%(message)s'))
log.addHandler(handler)


class DynectTestCase(TestCase):

    def setUp(self):

        def urlopen(s, method, url, body=None, headers=None, retries=3,
                    redirect=True, assert_same_host=True, timeout=_Default,
                    pool_timeout=None, release_conn=None, **response_kw):

            log.info("%s request to %s" % (method, url))

            # Build fake response
            fake_response = HTTPResponse(
                body=StringIO(self.responses[method][url]['body']),
                status=self.responses[method][url]['status'],
                preload_content=False)
            return fake_response

        # Patch connection pool
        self.patch_urllib3 = patch.object(
            HTTPSConnectionPool, 'urlopen', mocksignature=True)
        p = self.patch_urllib3.start()
        p.side_effect = urlopen

        # Reset dicts
        self.responses = {'GET': {}, 'POST': {}, 'PUT': {}, 'DELETE': {}}

        # # Mock start session.
        self.set_response(
            '/REST/Session/', 'post',
            '{"status": "success", "data": {"token": "abc"}}')

    def tearDown(self):
        # Stop patches.
        self.patch_urllib3.stop()

    def set_response(self, url, method, body, status=200):
        self.responses[method.upper()][url] = {
            'body': body, 'status': status}

    def test_authentication(self):
        " Test a correct authentication."

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')

        # Check token.
        self.assertEqual(dyn.auth.token, 'abc')

    def test_without_customer_name(self):
        " Missing fields must return an error."

        # Mock start session.
        self.set_response(
            '/REST/Session/', 'post',
            '{"status": "failure", "data": null, "job_id": null, "msgs": '\
            '[{"INFO": "user_name: required field missing", "SOURCE": '\
            '"API-A", "ERR_CD": "MISSING_DATA", "LVL": "ERROR"}, {"INFO": '\
            '"customer_name: required field missing", "SOURCE": "API-A", '\
            '"ERR_CD": "MISSING_DATA", "LVL": "ERROR"}, {"INFO": '\
            '"password: required field missing", "SOURCE": "API-A", '\
            '"ERR_CD": "MISSING_DATA", "LVL": "ERROR"}]}', 404)

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')
        self.assertRaises(dyn.auth.Failure, lambda: dyn.auth.token)

    def test_invalid_credentials(self):
        " Invalid credentials must lead to an exception."

        # Mock start session.
        self.set_response(
            '/REST/Session/', 'post',
            '{"status": "failure", "data": null, "job_id": null, "msgs": '\
            '[{"INFO": "login: Credentials you entered did not match '\
            'those in our database. Please try again", "SOURCE": '\
            '"BLL", "ERR_CD": "INVALID_DATA", "LVL": "ERROR"}]}', 404)

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')
        self.assertRaises(dyn.auth.CredentialsError, lambda: dyn.auth.token)

    def test_add_address(self):
        " Add an address."

        # Mock endpoint that add an address.
        self.set_response(
            '/REST/ARecord/test.com/test.com', 'post',
            '{"status": "success", "data": {"zone": "test.com", "ttl": '\
            '3600, "fqdn": "test.com", "record_type": "A", "rdata": '\
            '{"address": "2.2.2.2"}, "record_id": 0}}')

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')

        # Add an address.
        record = dyn.add_address('test.com', '2.2.2.2')
        self.assertEqual(record.fqdn, 'test.com')
        self.assertEqual(record.address, '2.2.2.2')
        self.assertEqual(record.ttl, 3600)

    def test_add_duplicated_address(self):
        " Add an address already in the dns."

        # Mock endpoint that add an address.
        self.set_response(
            '/REST/ARecord/test.com/test.com', 'post',
            '{"status": "success", "data": {"zone": "test.com", "ttl": '\
            '3600, "fqdn": "test.com", "record_type": "A", "rdata": '\
            '{"address": "2.2.2.2"}, "record_id": 0}}')

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')

        # Add an address.
        record = dyn.add_address('test.com', '2.2.2.2')
        self.assertEqual(record.fqdn, 'test.com')
        self.assertEqual(record.address, '2.2.2.2')
        self.assertEqual(record.ttl, 3600)

        # Mock to return a target_exist error.
        self.set_response(
            '/REST/ARecord/test.com/test.com', 'post',
            '{"status": "failure", "data": {}, "job_id": 52944102, '\
            '"msgs": [{"INFO": "make: Cannot duplicate existing record '\
            'data", "SOURCE": "DYN", "ERR_CD": "TARGET_EXISTS", "LVL": '\
            '"ERROR"}, {"INFO": "add: Record not added", "SOURCE": '\
            '"BLL", "ERR_CD": null, "LVL": "INFO"}]}')

        # Add an address.
        self.assertRaises(
            dyn.TargetExistsError, dyn.add_address, 'test.com', '2.2.2.2')

    def test_error_adding_address(self):
        "Error adding an address."

        # Mock endpoint that add an address.
        self.set_response(
            '/REST/ARecord/test.com/test.com', 'post',
            '{"status": "failure", "data": {}, "job_id": 52941596, '\
            '"msgs": [{"INFO": "address: Not a valid IP address", '\
            '"SOURCE": "DYN", "ERR_CD": "INVALID_DATA", "LVL": '\
            '"ERROR"}, {"INFO": "add: Could not create A record", '\
            '"SOURCE": "BLL", "ERR_CD": null, "LVL": "INFO"}]}', 400)

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')

        # Add an address.
        self.assertRaises(
            dyn.DynectError, dyn.add_address, 'test.com', '2.2.2.2222')

    def test_delete_address(self):
        " Delete an address."

        # Mock start session.
        self.set_response(
            '/REST/ARecord/test.com/test.com', 'get',
            '{"status": "success", "data": ['\
            '"/REST/ARecord/test.com/test.com/0"]}')

        self.set_response(
            '/REST/ARecord/test.com/test.com/0', 'get',
            '{"status": "success", "data": {"zone": "test.com", '\
            '"ttl": 3600, "fqdn": "test.com", "record_type": "A", '\
            '"rdata": {"address": "1.1.1.1"}, "record_id": 0}}')

        self.set_response(
            '/REST/ARecord/test.com/test.com/0', 'delete',
            '{"status": "success", "data": {}, "job_id": 52974126, '\
            '"msgs": [{"INFO": "delete: 1 records deleted", "SOURCE": '\
            '"API-B", "ERR_CD": null, "LVL": "INFO"}]}')

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')

        # Get a list of records.
        records = dyn.list_address('test.com')

        # Delete first entry.
        records[0].delete()

    def test_list_addresses(self):
        " List the address of a fqdn."

        # Mock start session.
        self.set_response(
            '/REST/ARecord/test.com/test.com', 'get',
            '{"status": "success", "data": ['\
            '"/REST/ARecord/test.com/test.com/0", '\
            '"/REST/ARecord/test.com/test.com/1", '\
            '"/REST/ARecord/test.com/test.com/2"]}')

        self.set_response(
            '/REST/ARecord/test.com/test.com/0', 'get',
            '{"status": "success", "data": {"zone": "test.com", '\
            '"ttl": 3600, "fqdn": "test.com", "record_type": "A", '\
            '"rdata": {"address": "1.1.1.1"}, "record_id": 0}}')

        self.set_response(
            '/REST/ARecord/test.com/test.com/1', 'get',
            '{"status": "success", "data": {"zone": "test.com", '\
            '"ttl": 3600, "fqdn": "test.com", "record_type": "A", '\
            '"rdata": {"address": "2.2.2.2"}, "record_id": 1}}')

        self.set_response(
            '/REST/ARecord/test.com/test.com/2', 'get',
            '{"status": "success", "data": {"zone": "test.com", '\
            '"ttl": 3600, "fqdn": "test.com", "record_type": "A", '\
            '"rdata": {"address": "3.3.3.3"}, "record_id": 2}}')

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')

        # Get a list of records.
        records = dyn.list_address('test.com')
        for i, record in enumerate(records):
            self.assertEqual(record.fqdn, 'test.com')
            self.assertEqual(record.address, '.'.join([str(i + 1)] * 4))
            self.assertEqual(record.ttl, 3600)

    def test_list_empty_addresses(self):
        " List an empty list of addresses."

        self.set_response(
            '/REST/ARecord/test.com/test.com', 'get',
            '{"status": "success", "data": []}')

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')
        addresses = dyn.list_address('test.com')
        self.assertEqual(addresses, [])

        self.set_response(
            '/REST/ARecord/test.com/test.com', 'get',
            '{"status": "failure", "data": {}, "msgs": [{"INFO": '\
            '"node: Not in zone", "SOURCE": "BLL", "ERR_CD": '\
            '"NOT_FOUND", "LVL": "ERROR"}]}')

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')
        addresses = dyn.list_address('test.com')
        self.assertEqual(addresses, [])

    def test_delete_node(self):
        " Delete a complete node."

        # Mock delete node.
        self.set_response(
            '/REST/Zone/test.com/www.test.com', 'delete',
            '{"status": "success", "data": {"zone_type": "Primary", '\
            '"serial_style": "day", "serial": 2012010700, "zone": '\
            '"test.com"}, "job_id": 52976457, "msgs": [{"INFO": '\
            '"remove_node: www.test.com removed from tree. All '\
            'records also removed.", "SOURCE": "BLL", "ERR_CD": '\
            'null, "LVL": "INFO"}]}')

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')

        # Get and delete node.
        node = dyn.get_node('www.test.com')
        job_id = node.delete()

        self.assertEqual(job_id, 52976457)

    def test_publish_changes(self):
        " Publish changes to Dynect."

        self.set_response(
            '/REST/Zone/test.com', 'put',
            '{"status": "success", "data": {"zone_type": "Primary", '\
            '"serial_style": "day", "serial": 2012010700, "zone": '\
            '"test.com"}, "job_id": 52972797, "msgs": [{"INFO": '\
            '"publish: test.com published", "SOURCE": "BLL", '\
            '"ERR_CD": null, "LVL": "INFO"}]}')

        # Start dynect.
        dyn = Dynect('customer', 'username', 'password', 'test.com')
        serial = dyn.publish()
        self.assertEqual(serial, 2012010700)
