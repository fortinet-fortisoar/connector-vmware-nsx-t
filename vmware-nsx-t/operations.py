""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('vmware-nsx-t')

error_msg = {401: 'Authentication failed due to invalid credentials',
             403: 'The user or team account does not have access to the endpoint/feature/resource',
             429: 'Rate limit was exceeded',
             "ssl_error": 'SSL certificate validation failed',
             'time_out': 'The request timed out while trying to connect to the remote server',
             }


class VMwareNSXT(object):
    def __init__(self, config):
        self.server_url = config.get('server_url', '').strip('/')
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = ('https://{0}'.format(self.server_url))
        self.username = config.get('username')
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, endpoint, params=None, payload=None, method='GET'):
        service_endpoint = '{0}{1}'.format(self.server_url, endpoint)
        logger.debug('API Request Endpoint: {0}'.format(service_endpoint))
        logger.debug('API Request Payload: {0}'.format(payload))
        logger.debug('API Request Params: {0}'.format(params))
        credentials = (self.username, self.password)
        try:
            response = requests.request(method, service_endpoint, auth=credentials, params=params, data=payload,
                                        verify=self.verify_ssl)
            logger.debug('API Status Code: {0}'.format(response.status_code))
            logger.debug('API Response: {0}'.format(response.text))
            if response.ok:
                return json.loads(response.content.decode('utf-8'))
            else:
                if error_msg.get(response.status_code):
                    logger.error("API Response: {0}".format(response.text))
                    raise ConnectorError('{0}'.format(error_msg.get(response.status_code)))
                else:
                    raise ConnectorError(response.text)
            response.raise_for_status()
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(error_msg.get('ssl_error')))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(error_msg.get('time_out')))
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def get_security_policies_list(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.pop('domain_id', '')
        endpoint = '/policy/api/v1/global-infra/domains/{0}/security-policies'.format(domain_id)
        query_params = {k: v for k, v in params.items() if v is not None and v != ''}
        return nsx.make_rest_call(endpoint, params=query_params)
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def get_security_policy_details(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.get('domain_id')
        policy_id = params.get('policy_id')
        endpoint = '/policy/api/v1/global-infra/domains/{0}/security-policies/{1}'.format(domain_id, policy_id)
        return nsx.make_rest_call(endpoint)
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def upsert_security_policy(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.pop('domain_id', '')
        policy_id = params.pop('policy_id', '')
        additional_field = params.pop('additional_field', '')
        endpoint = '/policy/api/v1/infra/domains/{0}/security-policies/{1}'.format(domain_id, policy_id)
        payload = {k: v for k, v in params.items() if v is not None and v != ''}
        payload.update({'resource_type': 'SecurityPolicy'})
        if additional_field:
            payload.update(additional_field)
        resp = nsx.make_rest_call(endpoint, payload=payload, method='PATCH')
        return {'status': 'success', 'result': 'Policy created/updated successfully.'} if not resp else resp
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def delete_security_policy(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.get('domain_id')
        policy_id = params.get('policy_id')
        endpoint = '/policy/api/v1/infra/domains/{0}/security-policies/{1}'.format(domain_id, policy_id)
        resp = nsx.make_rest_call(endpoint, method='DELETE')
        return {'status': 'success', 'result': 'Policy deleted successfully.'} if not resp else resp
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def get_groups_list(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.pop('domain_id', '')
        endpoint = '/policy/api/v1/global-infra/domains/{0}/groups'.format(domain_id)
        query_params = {k: v for k, v in params.items() if v is not None and v != ''}
        return nsx.make_rest_call(endpoint, params=query_params)
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def get_group_details(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.get('domain_id')
        group_id = params.get('group_id')
        endpoint = '/policy/api/v1/global-infra/domains/{0}/groups/{1}'.format(domain_id, group_id)
        return nsx.make_rest_call(endpoint)
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def upsert_group(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.pop('domain_id', '')
        group_id = params.pop('group_id', '')
        additional_field = params.pop('additional_field', '')
        endpoint = '/policy/api/v1/infra/domains/{0}/groups/{1}'.format(domain_id, group_id)
        payload = {k: v for k, v in params.items() if v is not None and v != ''}
        payload.update({'resource_type': 'Group'})
        if additional_field:
            payload.update(additional_field)
        resp = nsx.make_rest_call(endpoint, payload=payload, method='PATCH')
        return {'status': 'success', 'result': 'Group created/updated successfully.'} if not resp else resp
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def delete_group(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.get('domain_id')
        group_id = params.get('group_id')
        endpoint = '/policy/api/v1/infra/domains/{0}/groups/{1}'.format(domain_id, group_id)
        resp = nsx.make_rest_call(endpoint, method='DELETE')
        return {'status': 'success', 'result': 'Group deleted successfully.'} if not resp else resp
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def get_list_params(param):
    if param and isinstance(param, list):
        return param
    elif param and isinstance(param, str):
        return param.split(',')
    else:
        return []


def add_remove_ip_addresses(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.get('domain_id')
        group_id = params.get('group_id')
        expression_id = params.get('expression_id')
        action = params.get('action', '').lower()
        query_params = {'action': action}
        ip_addresses = get_list_params(params.get('ip_addresses'))
        request_body = {'ip_addresses': ip_addresses}
        endpoint = f'/policy/api/v1/infra/domains/{domain_id}/groups/{group_id}/ip-address-expressions/{expression_id}'
        resp = nsx.make_rest_call(endpoint, params=query_params, payload=request_body, method='POST')
        return {'status': 'success', 'result': 'IP addresses added successfully.'} if not resp else resp
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def add_remove_mac_addresses(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.get('domain_id')
        group_id = params.get('group_id')
        expression_id = params.get('expression_id')
        action = params.get('action', '').lower()
        query_params = {'action': action}
        mac_addresses = get_list_params(params.get('mac_addresses'))
        request_body = {'mac_addresses': mac_addresses}
        endpoint = f'/policy/api/v1/infra/domains/{domain_id}/groups/{group_id}/mac-address-expressions/{expression_id}'
        resp = nsx.make_rest_call(endpoint, params=query_params, payload=request_body, method='POST')
        return {'status': 'success', 'result': 'MAC addresses added successfully.'} if not resp else resp
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def get_rules_list(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.pop('domain_id', '')
        policy_id = params.pop('policy_id', '')
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        endpoint = f'/policy/api/v1/global-infra/domains/{domain_id}/security-policies/{policy_id}/rules'
        return nsx.make_rest_call(endpoint, params=params)
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def get_rule_details(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.get('domain_id', '')
        policy_id = params.get('policy_id', '')
        rule_id = params.get('rule_id', '')
        endpoint = f'/policy/api/v1/global-infra/domains/{domain_id}/security-policies/{policy_id}/rules/{rule_id}'
        return nsx.make_rest_call(endpoint)
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def upsert_rule(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.pop('domain_id', '')
        policy_id = params.pop('policy_id', '')
        rule_id = params.pop('rule_id', '')
        additional_field = params.pop('additional_field', '')
        params.update({'resource_type': 'Rule'})
        params['source_groups'] = get_list_params(params.get('source_groups'))
        params['scope'] = get_list_params(params.get('scope'))
        params['destination_groups'] = get_list_params(params.get('destination_groups'))
        endpoint = f"/policy/api/v1/infra/domains/{domain_id}/security-policies/{policy_id}/rules/{rule_id}"
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        resp = nsx.make_rest_call(endpoint, payload=params, method='PATCH')
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def delete_rule(config, params):
    try:
        nsx = VMwareNSXT(config)
        domain_id = params.get('domain_id')
        policy_id = params.get('policy_id')
        rule_id = params.get('rule_id', '')
        endpoint = f'/policy/api/v1/infra/domains/{domain_id}/security-policies/{policy_id}/rules/{rule_id}'
        resp = nsx.make_rest_call(endpoint, method="DELETE")
        return {'status': 'success', 'result': 'Rule deleted successfully.'} if not resp else resp
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)


def manage_vm_tag(config, params):
    try:
        nsx = VMwareNSXT(config)
        external_id = params.get('external_id')
        vm_tag_update_action = params.get('vm_tag_update_action')
        vm_scope = params.get('vm_scope')
        vm_tag = params.get('vm_tag')
        action_dict = {"ADD": "add_tags", "REMOVE": "remove_tags", "UPDATE": "update_tags"}
        if vm_tag_update_action == 'ADD':
            endpoint = f"/api/v1/fabric/virtual-machines?action={action_dict['ADD']}"
        elif vm_tag_update_action == 'REMOVE':
            endpoint = f"/api/v1/fabric/virtual-machines?action={action_dict['REMOVE']}"
        elif vm_tag_update_action == 'UPDATE':
            endpoint = f"/api/v1/fabric/virtual-machines?action={action_dict['UPDATE']}"
        params_dict = {"external_id": external_id, "tags": [{"scope": vm_scope, "tag": vm_tag}]}
        resp = nsx.make_rest_call(endpoint, payload=json.dumps(params_dict, indent = 4), method='POST')
        return json.dumps(resp)
    except Exception as Err:
        logger.error(Err)
        raise ConnectorError(Err)
    
def get_vm_externalID(config, params):
    try:
      nsx = VMwareNSXT(config)
      vm_name = params.get('vm_name')
      endpoint = f"/api/v1/fabric/virtual-machines?display_name={vm_name}&included_fields=tags&included_fields=external_id"
      resp = nsx.make_rest_call(endpoint, method='GET')
      return json.dumps(resp)
    except Exception as Err:
      logger.error(Err)
      raise ConnectorError(Err)


def _check_health(config):
    try:
        nsx = VMwareNSXT(config)
        resp = nsx.make_rest_call('/policy/api/v1/infra/drafts')
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


operations = {
    'get_security_policies_list': get_security_policies_list,
    'get_security_policy_details': get_security_policy_details,
    'upsert_security_policy': upsert_security_policy,
    'delete_security_policy': delete_security_policy,
    'get_groups_list': get_groups_list,
    'get_group_details': get_group_details,
    'upsert_group': upsert_group,
    'delete_group': delete_group,
    'add_remove_ip_addresses': add_remove_ip_addresses,
    'add_remove_mac_addresses': add_remove_mac_addresses,
    'get_rules_list': get_rules_list,
    'get_rule_details': get_rule_details,
    'upsert_rule': upsert_rule,
    'delete_rule': delete_rule,
    'manage_vm_tag': manage_vm_tag,
    'get_vm_externalID': get_vm_externalID

}

