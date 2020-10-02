import json
from bson import json_util
import logging
import uuid
from wsgiref import simple_server
import falcon
import requests
from pymongo import MongoClient
myclient = MongoClient('localhost', 27017)
mydb = myclient.RflowCollector
FlowCol = mydb.FlowRecord
Rules = mydb.FlowRule

class StorageEngine(object):

    def get_stat(self, rflow_object):
        return list(FlowCol.find(rflow_object))

    def add_rule(self, rflow_object):
        Rule = {"ID":rflow_object['ID'], "Layer":rflow_object['Layer'], "src_MAC":rflow_object['src_MAC'], "dst_MAC":rflow_object['dst_MAC'], 				"src_IP": rflow_object['src_IP'],"dst_IP": rflow_object['dst_IP'], "Porto":rflow_object['Proto'], 				"src_Port":rflow_object['src_Port'], "dst_Port":rflow_object['dst_Port'], 				"Priority":rflow_object['Priority'],"TimeWindow":rflow_object['TimeWindow'],"Threshold":rflow_object['Threshold'], 			"Action":rflow_object['Action']}
        if Rules.count_documents(Rule) == 0:
        	Rules.insert_one(Rule)
        return list(Rules.find())

class StorageError(Exception):

    @staticmethod
    def handle(ex, req, resp, params):
        description = ('Sorry, couldn\'t write your thing to the '
                       'database. It worked on my box.')

        raise falcon.HTTPError(falcon.HTTP_725,
                               'Database Error',
                               description)

class AuthMiddleware(object):

    def process_request(self, req, resp):
        token = req.get_header('Authorization')
        account_id = req.get_header('Account-ID')

        challenges = ['Token type="Fernet"']
        if token is None:
            description = ('Please provide an auth token '
                           'as part of the request.')
                           
            raise falcon.HTTPUnauthorized('Auth token required',
                                          description,
                                          challenges,
                                          href='http://docs.example.com/auth')

        if not self._token_is_valid(token, account_id):
            description = ('The provided auth token is not valid. '
                           'Please request a new token and try again.')

            raise falcon.HTTPUnauthorized('Authentication required',
                                          description,
                                          challenges,
                                          href='http://docs.example.com/auth')

    def _token_is_valid(self, token, account_id):
        return True  # All are valid...


class RequireJSON(object):

    def process_request(self, req, resp):
        if not req.client_accepts_json:
            raise falcon.HTTPNotAcceptable(
                'This API only supports responses encoded as JSON.',
                href='http://docs.examples.com/api/json')

        if req.method in ('POST', 'PUT'):
            if 'application/json' not in req.content_type:
                raise falcon.HTTPUnsupportedMediaType(
                    'This API only supports requests encoded as JSON.',
                    href='http://docs.examples.com/api/json')


class JSONTranslator(object):
    def process_request(self, req, resp):
        # req.stream corresponds to the WSGI wsgi.input environ variable,
        # and allows you to read bytes from the request body.
        #
        # See also: PEP 3333
        if req.content_length in (None, 0):
            # Nothing to do
            return

        body = req.bounded_stream.read()

        if not body:
            raise falcon.HTTPBadRequest('Empty request body',
                                        'A valid JSON document is required.')

        try:
            req.context.doc = json.loads(body.decode('utf-8'))

        except (ValueError, UnicodeDecodeError):
            raise falcon.HTTPError(falcon.HTTP_753,
                                   'Malformed JSON',
                                   'Could not decode the request body. The '
                                   'JSON was incorrect or not encoded as '
                                   'UTF-8.')

    def process_response(self, req, resp, resource, req_succeeded):
        if not hasattr(resp.context, 'result'):
            return
                   
        resp.body = json.dumps(resp.context.result, default=json_util.default)

def max_body(limit):

    def hook(req, resp, resource, params):
        length = req.content_length
        if length is not None and length > limit:
            msg = ('The size of the request is too large. The body must not '
                   'exceed ' + str(limit) + ' bytes in length.')

            raise falcon.HTTPPayloadTooLarge(
                'Request body is too large', msg)

    return hook


class ThingsResource(object):

    def __init__(self, db):
        self.db = db
        self.logger = logging.getLogger('RflowCollector.' + __name__)

    def on_get(self, req, resp, user_id):
        rflow_object = req.context.doc
        	
        if rflow_object['type'] == "Statistics":
            try:
            	del rflow_object['type']            
            	result = self.db.get_stat(rflow_object);	
            except Exception as ex:
            	self.logger.error(ex)

            	description = ('Fail to lookup flow records.')

            	raise falcon.HTTPServiceUnavailable(
                'Service Outage',
                description,
                30)

        resp.context.result = result
        resp.set_header('Powered-By', 'RFlow_Collector')
        resp.status = falcon.HTTP_200

    @falcon.before(max_body(64 * 1024))
    def on_post(self, req, resp, user_id):
        rflow_object = req.context.doc
        if rflow_object['type'] == "Control":
            try:
            	del rflow_object['type']
            	result = self.db.add_rule(rflow_object)
            except AttributeError:
            	raise falcon.HTTPBadRequest(
		        'Missing Rflow_object',
		        'A Rflow_object must be submitted in the request body.')
        #resp.context.result = result	
        resp.status = falcon.HTTP_201

# Configure your WSGI server to load "things.app" (app is a WSGI callable)
app = falcon.API(middleware=[
    AuthMiddleware(),
    RequireJSON(),
    JSONTranslator(),
])

db = StorageEngine()
Rflow_Collector = ThingsResource(db)
app.add_route('/{user_id}/rflow_collector', Rflow_Collector)


app.add_error_handler(StorageError, StorageError.handle)


if __name__ == '__main__':
    httpd = simple_server.make_server('127.0.0.1', 8000, app)
    httpd.serve_forever()
