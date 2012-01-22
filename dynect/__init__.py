import logging

log = logging.getLogger('dynect')

import requests
import json
from requests.auth import AuthBase
from decorator import decorator


class DynectAuth(AuthBase):

    # Some errors.
    class CredentialsError(Exception):
        pass

    class Failure(Exception):
        pass

    def __init__(self, customer, username, password):
        # Save authentication info.
        self.customer = customer
        self.username = username
        self.password = password

    @property
    def token(self):
        " Get token when needed."

        if hasattr(self, '_token'):
            return getattr(self, '_token')

        # Json formatted auth.
        data = json.dumps({'customer_name': self.customer,
                           'user_name': self.username,
                           'password': self.password})

        # Start session.
        response = requests.post(
            'https://api2.dynect.net/REST/Session/', data=data,
            headers={'Content-Type': 'application/json'})

        # convert to data.
        content = json.loads(response.content)

        if response.status_code != 200:
            # Check for errors.
            if self.check_error(content, 'failure', 'INVALID_DATA'):
                raise self.CredentialsError(
                    self.response_message(content, 'ERROR'))

            raise self.Failure(self.response_message(content, 'ERROR'),
                               'Unhandled failure')

        # Extract token from content
        if 'data' in content and 'token' in content['data']:
            token = content['data']['token']
        else:
            raise self.AuthenticationError(response)

        setattr(self, '_token', token)
        return token

    def parse_error(self, response):
        " Parse authentication errors."

        # Check invalid credentials.
        if self.check_error(response, 'failure', 'INVALID_DATA'):
            raise self.CredentialsError(
                self.response_message(response, 'ERROR'))

    def check_error(self, response, status, err_cd):
        " Check an error in the response."

        if 'status' not in response:
            return False

        if response['status'] != status:
            return False

        if 'msgs' not in response:
            return False

        if not isinstance(response['msgs'], list):
            return False

        for msg in response['msgs']:

            if 'LVL' in msg and msg['LVL'] != 'ERROR':
                continue

            if 'ERR_CD' in msg and msg['ERR_CD'] == err_cd:
                return True

        return False

    def response_message(self, response, lvl, default=''):

        if 'msgs' not in response:
            return default

        if not isinstance(response['msgs'], list):
            return default

        for msg in response['msgs']:
            if 'LVL' in msg and msg['LVL'] == lvl:
                return msg['INFO']

        return default

    def __call__(self, r):
        r.headers['Auth-Token'] = self.token
        r.headers['Content-Type'] = 'application/json'
        return r



@decorator
def login_required(f, self, *args, **kwargs):
    try:
        return f(self, *args, **kwargs)
    except self.auth.CredentialsError, e:
        raise e
    except:
        if hasattr(self.auth, '_token'):
            delattr(self.auth, '_token')
        return f(self, *args, **kwargs)


class Dynect(object):
    """
    Wrapper to all the interactions with the API.
    """

    class GeneralError(Exception):
        pass

    class NotFoundError(Exception):
        _name = "Not Found"

    class DynectError(Exception):
        _name = "Dynect API"

    class TargetExistsError(Exception):
        _name = "Target exists:"

    def __init__(self, customer, username, password, zone):

        # Create session object.
        self.auth = DynectAuth(customer, username, password)
        self.session = requests.Session(
            auth=self.auth, hooks={
                'response': self.hook_response,
                'args': self.hook_args,
                },
            headers={
                'Content-Type': 'application/json',
                })

        # Store the zone.
        self.zone = zone

    def hook_args(self, args):

        # Fix the url.
        args['url'] = 'https://api2.dynect.net' + args['url']

        # Add the correct content-type.
        args['data'] = json.dumps(args['data'])

        return args

    def hook_response(self, response):
        " Detect any failure."
        # Decode content with json.
        response._content = json.loads(response.content)
        return response

    def get(self, *args, **kwargs):
        response = self.session.get(*args, **kwargs)
        self.check_errors(response)
        return response

    def post(self, *args, **kwargs):
        response = self.session.post(*args, **kwargs)
        self.check_errors(response)
        return response

    def put(self, *args, **kwargs):
        response = self.session.put(*args, **kwargs)
        self.check_errors(response)
        return response

    def delete(self, *args, **kwargs):
        response = self.session.delete(*args, **kwargs)
        self.check_errors(response)
        return response

    def check_errors(self, response):
        " Check some common errors."

        # Read content.
        content = response.content

        if 'status' not in content:
            raise self.GeneralError('We expect a status field.')

        # Return the decoded content if status is success.
        if content['status'] == 'success':
            response._content = content
            return

        # Expect messages if some kind of error.
        if 'msgs' not in content:
            raise self.GeneralError('We expcet messages in case of error.')

        try:
            messages = list(content['msgs'])
        except:
            raise self.GeneralError("Messages must be a list.")

        # Try to found common errors in the response.
        for msg in messages:

            if 'LVL' in msg and msg['LVL'] == 'ERROR':

                # Check if is a not found error.
                if msg['ERR_CD'] == 'NOT_FOUND':
                    raise self.NotFoundError(msg['INFO'])

                # Duplicated target.
                elif msg['ERR_CD'] == 'TARGET_EXISTS':
                    raise self.TargetExistsError(msg['INFO'])

                # Some other error.
                else:
                    raise self.DynectError(msg['INFO'])

        raise self.GeneralError("We need at least one error message.")

    @login_required
    def add_address(self, fqdn, address, ttl=0):
        " Add a new address to a domain."

        data = {'rdata': {'address': address}, 'ttl': str(ttl)}

        # Make request.
        response = self.post('/REST/ARecord/%s/%s' % (
            self.zone, fqdn), data=data)

        return Address(self, data=response.content['data'])

    @login_required
    def publish(self):
        " Publish last changes."

        # Publish changes.
        response = self.put('/REST/Zone/%s' % (
            self.zone, ), data={'publish': True})

        return response.content['data']['serial']

    @login_required
    def list_address(self, domain):
        " Get the list of addresses of a single domain."

        try:
            response = self.get('/REST/ARecord/%s/%s' % (
                self.zone, domain))
        except self.NotFoundError:
            return []

        # Return a generator with the addresses.
        addresses = response.content['data']
        return [Address.from_url(self, uri) for uri in addresses]

    def remove_address(self, fqdn, address):
        " Remove an address of a domain."

        # Get a list of addresses.
        for record in self.list_address(fqdn):
            if record.address == address:
                record.delete()
                break

    def get_node(self, fqdn):
        " Get a node from the fqdn."

        return Node(self, fqdn=fqdn)

    def delete_node(self, fqdn):
        " Shorcut to delete a node."

        node = self.get_node(fqdn)
        return node.delete()


class Node(object):

    def __init__(self, dyn, fqdn):
        self.dyn = dyn
        self.fqdn = fqdn

    @property
    def url(self):
        return '/REST/NodeList/%s/%s' % (
            self.dyn.zone, self.fqdn)

    @property
    def delete_url(self):
        return '/REST/Node/%s/%s' % (
            self.dyn.zone, self.fqdn)

    def delete(self):
        " Delete the address."
        response = self.dyn.delete(self.delete_url)
        return response.content['job_id']


class DynectRecord(object):
    """
    This class represents a general record in the DNS. A particular record
    must define its _schema_data in order to expose the attributes in
    a proper way.
    """
    # Default values.
    _schema_data = {}

    def __init__(self, dyn, data=None, url=None):
        self.dyn = dyn
        self._data = data
        self._url = url

    @classmethod
    def from_url(cls, dyn, url):
        " Create address from a url, this is lazy."
        return cls(dyn, url=url)

    @classmethod
    def from_data(cls, dyn, data):
        " Create address from data retrieved from API."
        return cls(dyn, data=data)

    def _ensure_data(self):
        if self._data == None:
            self._data = self.dyn.get(self._url).content['data']

    def delete(self):
        " Delete the record."

        response = self.dyn.delete(self.url)
        return response.content['job_id']

    def __getattr__(self, name):
        " Get the record attribute from the real data from the API."

        if name not in self._schema_data:
            raise AttributeError(
                'This record has no attribute %s' % (name, ))

        # Get the field schema.
        schema = self._schema_data[name]

        # Ensure data.
        self._ensure_data()

        # Walk in data.
        data = self._data
        for field in schema.split('.'):
            if field not in data:
                raise AttributeError(
                    'This record has no attribute %s' % (name, ))
            data = data[field]

        # Finally return data
        return data


class Address(DynectRecord):
    " Define a lazy-object to get address information."

    _record_name = 'ARecord'
    _schema_data = {
        'fqdn': 'fqdn',
        'record_id': 'record_id',
        'address': 'rdata.address',
        'zone': 'zone',
        'ttl': 'ttl'}

    @property
    def url(self):
        return '/REST/ARecord/%s/%s/%d' % (
            self.zone, self.fqdn, self.record_id)
