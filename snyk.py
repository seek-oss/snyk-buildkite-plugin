import sys
import os
import json
import subprocess
import logging
import shutil

BOLD = '\033[1m'
UNBOLD = '\033[0;0m'

BLOCK = True
if 'BLOCK' in os.environ:
    if 'false' in os.environ['BLOCK']:
        BLOCK = False

severity_mapping = {
    'low': 0,
    'medium': 1,
    'high': 2
}

def configure_golang():
    print('Configuring golang')
    os.environ['GOPATH'] = '/'
    repository = os.environ['REPOSITORY']
    directory = '/src/github.com/{}'.format(repository)
    subprocess.run(['mkdir', '-p', directory])
    subprocess.run(['cp', '-R', repository, '/src/github.com/{}/..'.format(repository)])
    os.chdir('/src/github.com/{}'.format(repository))

def configure_node():
    print('Configuring node!\n')
    os.chdir(os.environ['REPOSITORY'])
    if 'NPM_TOKEN' in os.environ:
        with open('.npmrc', 'a') as f:
            f.write('//registry.npmjs.org/:_authToken={}'.format(os.environ['NPM_TOKEN']))
    subprocess.run(['npm', 'install', '-s'])

def configure_scala():
    print('Configuring scala!\n')
    gradle_properties='~/.gradle/gradle.properties'
    subprocess.run(['mkdir', '-p', '~/.gradle'])
    subprocess.run(['touch', gradle_properties])

    with open(gradle_properties, 'a') as f:
        f.write('artifactoryUsername={}\n'.format(os.environ['ARTIFACTORY_USERNAME']))
        f.write('artifactoryPassword={}\n'.format(os.environ['ARTIFACTORY_PASSWORD']))

    with open(gradle_properties) as f:
        print(f.read())

    os.chdir(os.environ['REPOSITORY'])

def snyk_test():
    EXIT_CODE = 0
    subprocess.run(['snyk', 'auth', os.environ['SNYK_TOKEN']])
    if 'DEPENDENCY_PATH' in os.environ:
        print('explicit path specified')
        results = (subprocess.run(['snyk', 'test', '--json', '--file={}'.format(os.environ['DEPENDENCY_PATH'])], stdout=subprocess.PIPE))
    else:
        print('no path specified')
        results = (subprocess.run(['snyk', 'test', '--json'], stdout=subprocess.PIPE))

    results = json.loads(results.stdout.decode())
    results_seen = {
        'low': {},
        'medium': {},
        'high': {}
    }

    # quit out if there are errors
    if 'error' in results.keys():
        print('Error: {}'.format(results['error']))
        sys.exit(1)

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

    # determine exit code
    blocking_severity = os.environ['SEVERITY']
    for severity in results_seen:
        if severity_mapping[blocking_severity] <= severity_mapping[severity] and len(results_seen[severity]) > 0:
            EXIT_CODE = 1
            # print('blocking severity: {}, severity found: {}'.format(severity_mapping[blocking_severity], severity_mapping[severity]))
    return EXIT_CODE

def print_env():
    print('LANGUAGE: {}'.format(os.environ['LANGUAGE']))
    print('REPOSITORY: {}'.format(os.environ['REPOSITORY']))
    print('ORG: {}'.format(os.environ['ORG']))

def snyk_monitor(organisation):
    if 'DEPENDENCY_PATH' in os.environ:
        result = (subprocess.run(['snyk', 'monitor', '--json', '--org={}'.format(organisation), '--file={}'.format(os.environ['DEPENDENCY_PATH'])], stdout=subprocess.PIPE))
    else:
        result = (subprocess.run(['snyk', 'monitor', '--json', '--org={}'.format(organisation)], stdout=subprocess.PIPE))
    result = json.loads(result.stdout.decode())
    message = 'Taking snapshot of project dependencies!\n'
    message += 'Vulnerabilities for the project can be found here: {}, where vulnerabilites can be ignored for subsequent scans.'.format(result['uri'].rsplit('/history')[0])
    print(message)

if __name__ == "__main__":
    EXIT_CODE = 1
    try:
        print_env()
        eval('configure_{}()'.format(os.environ['LANGUAGE']))   
        EXIT_CODE = snyk_test()
        snyk_monitor(os.environ['ORG'])
    except Exception as e:
        print('error: {}'.format(e))
        sys.exit(1)

    if not BLOCK:
        print('exit 0')
        exit(0)
    else:
        print('exit {}'.format(EXIT_CODE))
        exit(EXIT_CODE)