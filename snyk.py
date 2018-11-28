import sys
import os
import json
import subprocess
import logging
import shutil
import boto3

BOLD = '\033[1m'
UNBOLD = '\033[0;0m'

MONITOR_SUCCESS = None
TEST_SUCCESS = None
EVENTS = {
    'fail': 'snyk.scan.fail',
    'pass': 'snyk.scan.pass',
    'error': 'snyk.scan.error'
}

# extract out environment variables for safe usage
try:
    # mandatory fields
    REPOSITORY = os.environ['REPOSITORY']
    LANGUAGE = os.environ['LANGUAGE']
    VERSION = os.environ['VERSION']
    PLUGIN_NAME = os.environ['PLUGIN_NAME']
    METRICS_TOPIC_ARN = os.environ['METRICS_TOPIC_ARN']

    NPM_TOKEN = os.environ['NPM_TOKEN'] if 'NPM_TOKEN' in os.environ else ''

    ORG = os.environ['ORG'] if 'ORG' in os.environ else ''
    BLOCK = False if 'BLOCK' in os.environ and 'false' in os.environ['BLOCK'] else True
    PATH = os.environ['DEPENDENCY_PATH'] if 'DEPENDENCY_PATH' in os.environ else ''
    SEVERITY = os.environ['SEVERITY'] if 'SEVERITY' in os.environ else ''
    SCAN_DEV_DEPS = 'SCAN_DEV_DEPS' in os.environ and 'true' == os.environ['SCAN_DEV_DEPS']
    EVENT_DATA = {
        'version': VERSION,
        'repository': REPOSITORY,
        'org': ORG,
        'language': LANGUAGE,
        'block': BLOCK,
        'path': PATH,
        'severity': SEVERITY,
        'scanDevDeps': SCAN_DEV_DEPS
    }

except Exception as e:
    print('failed to extract environment variables: {}'.format(e))
    sys.exit(0)

SEVERITY_MAPPING = {
    'low': 0,
    'medium': 1,
    'high': 2
}

def configure_golang():
    print('Configuring golang')
    os.environ['GOPATH'] = '/'
    repository = REPOSITORY
    directory = '/src/github.com/{}'.format(repository)
    subprocess.run(['mkdir', '-p', directory])
    subprocess.run(['cp', '-R', repository, '/src/github.com/{}/..'.format(repository)])
    os.chdir('/src/github.com/{}'.format(repository))

def configure_node():
    print('Configuring node!\n')
    os.chdir(REPOSITORY)
    if NPM_TOKEN:
        with open('.npmrc', 'a') as f:
            f.write('//registry.npmjs.org/:_authToken={}'.format(NPM_TOKEN))
    subprocess.run(['npm', 'install', '-s'])

def configure_scala():
    print('Configuring scala!\n')
    gradle_properties='{}/gradle.properties'.format(REPOSITORY)
    with open(gradle_properties, 'a') as f:
        f.write('artifactoryUsername={}\n'.format(os.environ['ARTIFACTORY_USERNAME']))
        f.write('artifactoryPassword={}\n'.format(os.environ['ARTIFACTORY_PASSWORD']))
    os.chdir(REPOSITORY)

def snyk_test():
    EXIT_CODE = 0
    command = ['snyk', 'test', '--json']
    if PATH:
        print('explicit path specified')
        command.append('--file={}'.format(PATH))
    if SCAN_DEV_DEPS:
        command.append('--dev')

    response = subprocess.run(command, stdout=subprocess.PIPE)
    results = json.loads(response.stdout.decode())
    results_seen = {
        'low': {},
        'medium': {},
        'high': {}
    }

    global TEST_SUCCESS
    TEST_SUCCESS = False if 'error' in results.keys() else True
    if not TEST_SUCCESS:
        raise Exception('snyk test returned an error')

    for result in results['vulnerabilities']:
        introduced_from = result['from']
        severity = result['severity']
        if result['id'] in results_seen[severity]:
            results_seen[severity][result['id']]['from'].append(result['from'])
            results_seen[severity][result['id']]['upgradePath'].append(result['upgradePath'])
        else:
            results_seen[severity][result['id']] = {
                'moduleName': result['moduleName'],
                'title': result['title'],
                'severity': result['severity'],
                'isUpgradable': result['isUpgradable'],
                'isPatchable': result['isPatchable'],
                'from': [introduced_from], 
                'upgradePath': [result['upgradePath']]
            }
    
    # vulnerability metrics
    EVENT_DATA['vulnCount'] = results['uniqueCount']
    EVENT_DATA['vulnHigh'] = len(results_seen['high'].keys())
    EVENT_DATA['vulnMedium'] = len(results_seen['medium'].keys())
    EVENT_DATA['vulnLow'] = len(results_seen['low'].keys())

    vulnerable_paths = 0
    for severity in results_seen.keys():
        for key in results_seen[severity].keys():
            result = results_seen[severity][key]
            introduced_value = []
            for dependency_tree in result['from']:
                introduced_value.append(dependency_tree[1])
            message = '{}{} severity found in {}{}\n'.format(BOLD, result['severity'].capitalize(), result['moduleName'], UNBOLD)
            message += ' -> Description: {}\n'.format(result['title'])
            message += ' -> Info: https://snyk.io/vuln/{}\n'.format(key)
            message += ' -> Introduced through: {}\n'.format(', '.join(introduced_value[:5]))

            vulnerable_paths += len(result['from'])

            for from_list in result['from'][:3]:
                message += ' -> From: {}\n'.format(' > '.join(from_list[:3]))

            if len(result['from']) > 3:
                message += ' -> and {} more...\n'.format(len(result['from']) - 3)

            if result['isUpgradable']:
                message += BOLD + 'Remediation: \n\t Upgrade {} to {} (triggers upgrades to {})\n'.format(result['from'][0][1], result['upgradePath'][0][1], ' > '.join(result['upgradePath'][0][1:])) + UNBOLD
            print(message)
    
    summary = 'Tested {} dependencies for known issues, found {} issues, {} vulnerable paths\n'.format(results['dependencyCount'], results['uniqueCount'], vulnerable_paths)
    print(summary)

    for severity in results_seen:
        if SEVERITY_MAPPING[SEVERITY] <= SEVERITY_MAPPING[severity] and len(results_seen[severity]) > 0:
            EXIT_CODE = 1
    return EXIT_CODE

def snyk_monitor(organisation):
    command = ['snyk', 'monitor', '--json', '--org={}'.format(organisation)]
    if PATH:
        command.append('--file={}'.format(PATH))
    if SCAN_DEV_DEPS:
        command.append('--dev')
    response = subprocess.run(command, stdout=subprocess.PIPE)
    result = json.loads(response.stdout.decode())
    
    global MONITOR_SUCCESS
    MONITOR_SUCCESS = False if 'error' in result.keys() else True
    if not MONITOR_SUCCESS:
        raise Exception('snyk monitor returned an error')

    message = 'Taking snapshot of project dependencies!\n'
    message += 'Vulnerabilities for the project can be found here: {}, where vulnerabilites can be ignored for subsequent scans.'.format(result['uri'].rsplit('/history')[0])
    print(message)

def send_metrics(event_name, error_message=None):
    try:
        sns_client = boto3.client('sns', region_name='ap-southeast-2')
        # add additional fields to event data
        EVENT_DATA['testSuccess'] = TEST_SUCCESS
        EVENT_DATA['monitorSuccess'] = MONITOR_SUCCESS
        if error_message:
            EVENT_DATA['error_message'] = error_message

        event = {
            'type': event_name,
            'source': PLUGIN_NAME,
            'data': EVENT_DATA
        }
        sns_client.publish(
            TopicArn=METRICS_TOPIC_ARN,
            Message=json.dumps(event)
        )
    except Exception as e:
        print('error sending metrics: {}'.format(e))
        exit(0)

if __name__ == "__main__":
    EXIT_CODE = None
    try:
        eval('configure_{}()'.format(LANGUAGE))
        subprocess.run(['snyk', 'auth', os.environ['SNYK_TOKEN']])
    except Exception as e:
        print('config error: {}'.format(e))
        send_metrics(event_name=EVENTS['error'], error_message=e)
        exit(0)

    for attempt in range(0,3):
        try:
            EXIT_CODE = snyk_test()
            snyk_monitor(ORG)
        except Exception as e:
            print('{}'.format(e))
            EXIT_CODE = None
            continue
        break

    if not EXIT_CODE:
        send_metrics(event_name=EVENTS['error'], error_message='snyk test and monitor did not both succeed')
        exit(0)
    elif EXIT_CODE == 0:
        send_metrics(event_name=EVENTS['pass'])
        exit(0)
    elif EXIT_CODE == 1:
        send_metrics(event_name=EVENTS['fail'])
        if BLOCK:
            exit(1)
        exit(0)