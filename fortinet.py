#!/usr/bin/env python3

"""Be sure to configure all values in the config file before running
this script. After running it, be sure to move the policy to the desired
position in the policy list on your FortiGate client (probably the top).

Alternatively, you can create a policy manually in FortiGate with the
same names as the ones specified (host_policy_name and detection_policy_name)
and this script will update the policy accordingly.
"""

import sys
try:
    import requests
    import argparse
    import datetime
    import json
    import logging.handlers
    import pyfortiapi
    from requests import HTTPError
    from enum import Enum, unique, auto
    from config import COGNITO_URL, COGNITO_TOKEN, FORTI_INFO
except ImportError as error:
    sys.exit('\nMissing import requirements: {}\n'.format(str(error)))


@unique
class BlockType(Enum):
    """Enumerated type describing the kind of block to be done
    on FortiGate. FortiGate can block source and destination
    addresses.
    """
    SOURCE = auto()
    DESTINATION = auto()


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

dst_group_name = 'Cognito Blocked Destinations'
src_group_name = 'Cognito Blocked Sources'

vectra_page_size = '200'
host_search_uri = '/api/v2/search/hosts/'
host_tag_uri = '/api/v2/tagging/host/'
detection_search_uri = '/api/v2/search/detections/'
detection_tag_uri = '/api/v2/tagging/detection/'

vectra_header = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
    'Authorization': 'Token ' + COGNITO_TOKEN
}

allowed_detection_categories = ['COMMAND & CONTROL', 'EXFILTRATION']
alternate_detection_types = ['Hidden DNS Tunnel', 'Suspect Domain Activity', 'Suspicious HTTP',
                             'Abnormal Ad Activity', 'Abnormal Web Activity']


def contains_tag(block_type, id, c_tag):
    uri = host_tag_uri if block_type == BlockType.SOURCE else detection_tag_uri
    url = COGNITO_URL + uri + str(id)
    tags = requests.get(url=url, headers=vectra_header, verify=False).json()['tags']
    return any(c_tag in tag for tag in tags)


def poll_vectra(block_type, url, params=None, headers=vectra_header):
    """Retrieve data from Cognito"""
    if params is None:
        params = {}
    params.update({'page_size': vectra_page_size})
    response = requests.get(url, headers=headers, params=params, verify=False)
    try:
        response.raise_for_status()
        results = response.json()['results']
    except (HTTPError, json.JSONDecodeError) as e:
        logger.info('Unable to retrieve Cognito data')
        raise e

    item_dict = {}
    if block_type == BlockType.SOURCE:
        for item in results:
            item_dict.update({item['id']: [item['last_source']]})
    elif block_type == BlockType.DESTINATION:
        for item in results:
            detection_category = item['detection_category']
            if item['detection_category'] in allowed_detection_categories:
                if item['detection_type'] in alternate_detection_types:
                    ip_list = []
                    for group in item['grouped_details']:
                        ip_list.extend(group['dst_ips'])
                        if len(ip_list) != 0:
                            item_dict.update({item['id']: ip_list})
                else:
                    try:
                        item_dict.update({item['id']: item['summary']['dst_ips']})
                    except Exception:
                        logger.info(
                            'Not able to block destinations for detection type: %s', item['detection_type'])
            else:
                logger.info(
                    'Detection Category \'%s\' not supported for this action', detection_category)

    return item_dict


def register_addresses(firewall, block_type, id, ip_list, tag):
    """Register IP with FortiGate if not already registered"""
    tagged = contains_tag(block_type, id, 'Blocked:manual')
    for ip in ip_list:
        address = firewall.get_firewall_address(ip)
        if type(address) == int:
            if address == 404:
                data = json.dumps(
                    {'name': ip, 'type': 'iprange', 'start-ip': ip, 'end-ip': ip})
                firewall.create_firewall_address(ip, data)
                address = firewall.get_firewall_address(ip)[0]
                logger.debug('Address %s registered with FortiGate', address['name'])
                if not tagged:  # only tag if new address is created, and only once
                    update_tags(block_type, id, append=tag)
                    tagged = True
            else:
                raise HTTPError(address, 'Error retrieving address data')


def update_cognito_group(firewall, block_type, ips):
    """Update/Create address group based on block type"""
    ip_list = []
    b_tag = get_cognito_tag(blocked=True)

    for id, ip_l in ips.items():
        register_addresses(firewall, block_type, id, ip_l, b_tag)
        for ip in ip_l:
            ip_list.append({'name': ip})

    group_name = src_group_name if block_type == BlockType.SOURCE else dst_group_name
    group = firewall.get_address_group(group_name)

    if type(group) == int:
        if group == 404:
            data = json.dumps({'name': group_name, 'member': ip_list})
            firewall.create_address_group(group_name, data)
            group = firewall.get_address_group(group_name)[0]
            logger.debug('Address Group \'%s\' created', group['name'])
        else:
            raise HTTPError(group, 'Error retrieving group data')
    else:
        new_list = group[0]['member'] + ip_list
        data = json.dumps({'member': new_list})
        firewall.update_address_group(group_name, data)

    return firewall.get_address_group(group_name)[0]


def block_ips(firewalls, block_type, ips):
    """Block a list of IP addresses, either as source IPs or
    destination IPs
    """
    for firewall in firewalls:
        update_cognito_group(firewall, block_type, ips)


def unblock_ips(firewalls, block_type, ips):
    """Unblock either source or destination IP addresses by removing
    them from the FortiGate firewall policy
    """
    error_tag = 'not eligible to be unblocked'
    group_name = src_group_name if block_type == BlockType.SOURCE else dst_group_name
    u_tag = get_cognito_tag(blocked=False)
    for firewall in firewalls:
        ip_list = firewall.get_address_group(group_name)[0]['member']
        for id, ip_l in ips.items():
            tagged = contains_tag(block_type, id, 'Unblocked:manual')
            for ip in ip_l:
                try:
                    ip_list.remove({'name': ip, 'q_origin_key': ip})
                    if not tagged:  # only tag if IP is successfully deleted
                        update_tags(block_type, id, append=u_tag)
                        tagged = True
                except ValueError:  # IP wasn't blocked
                    update_tags(block_type, id, append=error_tag)

        data = json.dumps({'member': ip_list})
        firewall.update_address_group(group_name, data)

        for id, ip_l in ips.items():
            for ip in ip_l:  # deregister ips from FortiGate
                firewall.delete_firewall_address(str(ip))


def update_tags(block_type, id, append=False, remove=False):
    """Add a tag to either a host or a detection in Cognito indicating that
    is has been blocked or unblocked on the firewall
    """
    uri = host_tag_uri if block_type == BlockType.SOURCE else detection_tag_uri
    url = COGNITO_URL + uri + str(id)
    logger.debug('Update_tags url:%s', url)
    tags = requests.get(url=url, headers=vectra_header, verify=False).json()['tags']
    if append:
        tags.append(append)
    if remove:
        tags.remove(remove)
    body = json.dumps({'tags': tags})
    requests.patch(url=url, headers=vectra_header, data=body, verify=False)


def get_cognito_tag(blocked=True):
    """Generate a tag for Cognito indicating that a host
    or detection has been blocked or unblocked
    """
    return ('Blocked' if blocked else 'Unblocked') + ':manual ' + datetime.datetime.now().strftime('%Y-%d-%b %H:%M:%S')


def block_hosts(firewalls, tag, cognito_url):
    """Block all hosts with a specified tag in Cognito"""
    logger.info('Collecting hosts to block with Tag: %s', tag)
    cognito_full_url = cognito_url + host_search_uri
    params = {'query_string': 'host.state:"active"' \
                              ' AND host.tags:"%s"' \
                             r' AND NOT host.tags:unblocked\:manual' \
                             r' AND NOT host.tags:blocked\:manual' % tag}

    hosts = poll_vectra(BlockType.SOURCE, cognito_full_url, params)
    if len(hosts) > 0:
        block_ips(firewalls, BlockType.SOURCE, hosts)
    else:
        logger.info('No hosts to block from tag: %s', tag)
    # get all hosts with 'tag', even unblockable ones (so tag can be removed)
    params = {'query_string': 'host.tags:"{}"'.format(tag)}
    hosts = poll_vectra(BlockType.SOURCE, cognito_full_url, params)
    for host in hosts:
        update_tags(BlockType.SOURCE, host, remove=tag)


def block_host_tc(firewalls, tc, cognito_url):
    """Block all hosts with a Cognito threat and certainty score at or above
    the specified level
    """
    logger.info('Collecting hosts with Threat:%s Certainty:%s', tc[0], tc[1])
    cognito_full_url = cognito_url + host_search_uri
    params = {'query_string': 'host.state:"active"' \
                              ' AND host.threat:>=%s and host.certainty:>=%s' \
                             r' AND NOT host.tags:unblocked\:manual' \
                             r' AND NOT host.tags:blocked\:manual' % (tc[0], tc[1])}
    hosts = poll_vectra(BlockType.SOURCE, cognito_full_url, params)
    if len(hosts) > 0:
        block_ips(firewalls, BlockType.SOURCE, hosts)
    else:
        logger.info('No Hosts to block with given Threat and Certainty scores')


def block_detections(firewalls, tag, cognito_url):
    logger.info('Collecting detections to block with Tag: %s', tag)
    cognito_full_url = cognito_url + detection_search_uri
    params = {'query_string': 'detection.state:"active"' \
                              ' AND detection.tags:"%s"' \
                             r' AND NOT detection.tags:unblocked\:manual' \
                             r' AND NOT detection.tags:blocked\:manual' % tag}
    detections = poll_vectra(BlockType.DESTINATION, cognito_full_url, params)
    if len(detections) > 0:
        block_ips(firewalls, BlockType.DESTINATION, detections)
    else:
        logger.info('No detections to block from tag: %s', tag)
    # get all detections with 'tag', even unblockable ones (so tag can be removed)
    params = {'page_size': vectra_page_size, 'query_string': 'detection.tags:"{}"'.format(tag)}
    try:
        results = requests.get(cognito_full_url, headers=vectra_header, params=params, verify=False).json()['results']
        for detection in results:
            update_tags(BlockType.DESTINATION, detection['id'], remove=tag)
    except (HTTPError, json.JSONDecodeError):
        pass


def block_detection_type(firewalls, detection_type, cognito_url):
    """Block all destinations from a specified detection type in Cognito"""
    logger.info('Collecting detections with Detection Type: %s', detection_type)
    cognito_full_url = cognito_url + detection_search_uri
    params = {'query_string': 'detection.state:"active"'
                              ' AND detection.detection_type:"%s"' \
                             r' AND NOT detection.tags:unblocked\:manual' \
                             r' AND NOT detection.tags:blocked\:manual' % detection_type}
    detections = poll_vectra(BlockType.DESTINATION, cognito_full_url, params)
    if len(detections) > 0:
        block_ips(firewalls, BlockType.DESTINATION, detections)
    else:
        logger.info('No IPs to block with Detection Type: %s', detection_type)


def unblock_hosts(firewalls, tag, cognito_url):
    """Unblock all hosts in Cognito with a specified tag"""
    logger.info('Collecting hosts to unblock with Tag:%s', tag)
    cognito_full_url = cognito_url + host_search_uri
    params = {'query_string': 'host.tags:"{}"'.format(tag)}
    hosts = poll_vectra(BlockType.SOURCE, cognito_full_url, params)
    if len(hosts) > 0:
        unblock_ips(firewalls, BlockType.SOURCE, hosts)
    else:
        logger.info('No Hosts to unblock with tag: %s', tag)
    for host in hosts:
        update_tags(BlockType.SOURCE, host, remove=tag)


def unblock_detections(firewalls, tag, cognito_url):
    """Unblock all destinations in Cognito with a specified tag in their detection page"""
    logger.info('Collecting detections to unblock with Tag:%s', tag)
    cognito_full_url = cognito_url + detection_search_uri
    params = {'query_string': 'detection.tags:"{}"'.format(tag)}
    detections = poll_vectra(BlockType.DESTINATION, cognito_full_url, params)
    if len(detections) > 0:
        unblock_ips(firewalls, BlockType.DESTINATION, detections)
    else:
        logger.info('No detections to unblock with tag: %s', tag)
    for detection in detections:
        update_tags(BlockType.DESTINATION, detection, remove=tag)


def config_args():
    """Parse CLI arguments"""
    parser = argparse.ArgumentParser(description='Add or remove hosts from dynamic block list.',
                                     prefix_chars='-', formatter_class=argparse.RawTextHelpFormatter,
                                     epilog='Example: fortinet.py https://vectra.local AAAAAAAA https://fortinetfw.local '
                                     'admin **** --block_host_tag block')
    parser.add_argument('--block_host_tag', type=str, default=False,
                        help='Poll for tagged hosts to block, eg --block_host_tag block')
    parser.add_argument('--block_host_tc', type=int, nargs=2, default=False,
                        help='Poll for hosts with threat and certainty scores >= to block, eg --block_host_tc 50 50')
    parser.add_argument('--block_detection_tag', type=str, default=False,
                        help='Poll for tagged detections to block, eg --block_detection_tag block')
    parser.add_argument('--block_detection_type', type=str, default=False,
                        help='Poll for detection types to block')
    parser.add_argument('--unblock_host_tag', type=str, default=False,
                        help='Poll for tagged hosts to unblock, eg --unblock_host_tag unblock')
    parser.add_argument('--unblock_detection_tag', type=str, default=False,
                        help='Poll for tagged detections to unblock, eg --unblock_detection_tag unblock')

    return parser.parse_args()


def main():
    args = config_args()
    try:
        firewalls = []
        for auth in FORTI_INFO:
            firewalls.append(pyfortiapi.FortiGate(auth['IP'], auth['USER'], auth['PASS']))
    except KeyError as e:
        logger.error('Please configure firewall instances in config.py')
        raise e

    url = COGNITO_URL

    if args.block_host_tag:
        block_hosts(firewalls, args.block_host_tag, url)
    if args.block_host_tc:
        block_host_tc(firewalls, args.block_host_tc, url)
    if args.block_detection_tag:
        block_detections(firewalls, args.block_detection_tag, url)
    if args.block_detection_type:
        block_detection_type(firewalls, args.block_detection_type, url)
    if args.unblock_host_tag:
        unblock_hosts(firewalls, args.unblock_host_tag, url)
    if args.unblock_detection_tag:
        unblock_detections(firewalls, args.unblock_detection_tag, url)


if __name__ == '__main__':
    main()
