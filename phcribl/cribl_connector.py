#!/usr/bin/python
# -*- coding: utf-8 -*-

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from cribl_consts import *
import requests
import json
from bs4 import BeautifulSoup
import jwt
import time


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CriblConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CriblConnector, self).__init__()

        self._state = None
        self._job_id = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self.config = None
        self._app_version = self.get_app_json().get('app_version', '')

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", authenticated=True, worker_group=False, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        wg = ''
        if worker_group and self.config.get('worker_group'):
            wg = '/m/{}'.format(self.config.get('worker_group'))

        url = '{}/api/v1{}{}'.format(self.config['master_url'], wg, endpoint)
        self.save_progress('{} {}'.format(method.upper(), url))

        default_headers = {
            'User-Agent': 'Phantom app for Cribl/{}'.format(self._app_version),
            'Accept': 'application/json'
        }

        headers = default_headers.copy()
        if kwargs.get('headers'):
            headers.update(kwargs.pop('headers'))

        if authenticated:
            # We must have a token, and the token must still be valid!
            if not (self._state.get('token') and self._state['token']['exp'] > int(time.time())):
                ret_val, token_data = self._handle_login(action_result)

                if phantom.is_fail(ret_val):
                    return RetVal(
                        action_result.set_status(
                            phantom.APP_ERROR, "Error authenticating to Cribl master."
                        ), resp_json
                    )

                self._state['token'] = token_data

            headers.update({'Authorization': 'Bearer {}'.format(self._state['token']['token'])})

        try:
            r = request_func(
                url,
                verify=self.config['verify_server_cert'],
                headers=headers,
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_login(self, action_result):
        endpoint = '/auth/login'

        data = {
            'username': self.config['username'],
            'password': self.config['password']
        }

        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", authenticated=False, json=data)

        if phantom.is_fail(ret_val):
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to authenticate to the Cribl master node!"
                ), None
            )

        tok = jwt.decode(response['token'], options={'verify_signature': False})

        token_data = {
                'token': response['token'],
                'exp': tok['exp']
            }

        return ret_val, token_data

    def _get_collector_config(self, collector, action_result):
        endpoint = '/lib/jobs/{}'.format(collector)
        ret_val, response = self._make_rest_call(endpoint, action_result, worker_group=True)

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to get collector configuration for collector {}. Response: {}".format(collector,
                                                                                                             response))
            return action_result.set_status(phantom.APP_ERROR)

        if response["count"] == 0:
            self.save_progress("Configuration for collector \"{}\" was not found".format(collector))
            return action_result.set_status(phantom.APP_ERROR)

        action_result.set_status(phantom.APP_SUCCESS)

        return response["items"][0]

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # make rest call
        ret_val, response = self._make_rest_call(
            '/health', action_result, authenticated=False
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        if response.get("status") == "healthy":
            self.save_progress("Test Connectivity Passed.")
        else:
            self.save_progress("Test Connectivity Failed.")
            return action_result.set_status(phantom.APP_ERROR)

        ret_val, response = self._handle_login(action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Login Failed.")
            return action_result.get_status()

        if response.get("exp") > 0:
            self.save_progress("Test Login Passed.")
        else:
            self.save_progress("Test Login Failed.")
            return action_result.set_status(phantom.APP_ERROR)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_collector_job(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        collector = param['collector']
        filter = param['filter']
        timeRangeType = param['timeRangeType']
        earliest = param.get('earliest', '')
        latest = param.get('latest', '')

        collector_config = self._get_collector_config(collector, action_result)

        if phantom.is_fail(action_result.get_status()):
            return action_result.set_status(phantom.APP_ERROR,
                                            "Unable to correctly obtain the log collector configuration.")

        data = {
            **collector_config,
            "run": {
                "capture": {
                    "duration": 60,
                    "maxEvents": 100,
                    "level": "0"
                },
                "logLevel": "info",
                "minTaskSize": "1MB",
                "mode": "run",
                "expression": "{}".format(filter),
                "maxTaskSize": "10MB",
                "timeRangeType": "{}".format(timeRangeType),
                "earliest": "{}".format(earliest),
                "latest": "{}".format(latest)
            }
        }

        # make rest call
        ret_val, response = self._make_rest_call('/jobs', action_result, method="post", json=data, worker_group=True)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        if response.get('count') == 1:
            self._job_id = response['items'][0]
            self.save_progress('Created collector job ID {}'.format(self._job_id))

            # Poll for job completion
            if param.get('waitForJobCompletion', False):
                while True:
                    endpoint = '/jobs/{}'.format(self._job_id)
                    ret_val, response = self._make_rest_call(endpoint, action_result, worker_group=True)
                    job_status = response['items'][0]['status']['state']
                    self.save_progress('Job status = {}'.format(job_status))
                    if job_status not in ['pending', 'running']:
                        if job_status == 'failed':
                            return action_result.set_status(phantom.APP_ERROR,
                                                            "Job failed! Response data: {}".format(response))
                        if job_status == 'finished':
                            self.save_progress('Events collected = {}'.format(
                                response['items'][0]['stats']['discoveredEvents']))
                        break
                    time.sleep(5)
        else:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Job failed to create successfully! Response data: {}".format(response))

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'run_collector_job':
            ret_val = self._handle_run_collector_job(param)

        return ret_val

    def handle_cancel(self):
        self.save_progress('handle_cancel called')

        if self._job_id:
            endpoint = '/jobs/{}/cancel'.format(self._job_id)

            self._make_rest_call(endpoint, ActionResult(), method="patch", worker_group=True)

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        self.config = self.get_config()

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = CriblConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CriblConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
