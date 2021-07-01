from enum import Enum
import os
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import pprint
import sys
import json

SUPPORTED_SCANNERS = ["zap", "wapiti"]

OWASP_CRS_RULES_DIR = os.getenv('OWASP_CRS_DIR') + "/rules/"

LDAPI_CONF = OWASP_CRS_RULES_DIR + 'REQUEST-921-PROTOCOL-ATTACK.conf' # We only care about rule 921200/tag:language-ldap
LFI_CONF = OWASP_CRS_RULES_DIR + 'REQUEST-930-APPLICATION-ATTACK-LFI.conf'
RFI_CONF = OWASP_CRS_RULES_DIR + 'REQUEST-931-APPLICATION-ATTACK-RFI.conf'
RCE_CONF = OWASP_CRS_RULES_DIR + 'REQUEST-932-APPLICATION-ATTACK-RCE.conf'
PHP_CONF = OWASP_CRS_RULES_DIR + 'REQUEST-933-APPLICATION-ATTACK-PHP.conf'
XSS_CONF = OWASP_CRS_RULES_DIR + 'REQUEST-941-APPLICATION-ATTACK-XSS.conf'
SQLI_CONF = OWASP_CRS_RULES_DIR + 'REQUEST-942-APPLICATION-ATTACK-SQLI.conf'
BLOCKING_CONF = OWASP_CRS_RULES_DIR + 'REQUEST-949-BLOCKING-EVALUATION.conf'
CORRELATION_CONF = OWASP_CRS_RULES_DIR + 'RESPONSE-980-CORRELATION.conf'

LFI_TAG = "attack-lfi"
RFI_TAG = "attack-rfi"
RCE_TAG = "attack-rce"
PHP_TAG = "attack-injection-php"
XSS_TAG = "attack-xss"
SQLI_TAG = "attack-sqli"
LDAP_TAG = "language-ldap"
PROTOCOL_TAG = "attack-protocol"

ZAP_ALERT_XSS_REFL = "Cross Site Scripting (Reflected)";
ZAP_ALERT_XSS_PERS = "Cross Site Scripting (Persistent)";
ZAP_ALERT_SQLI = "SQL Injection";
ZAP_ALERT_LFI = "Path Traversal";
ZAP_ALERT_RFI = "Remote File Inclusion";
ZAP_ALERT_PHP = "Server Side Code Injection - PHP Code Injection";
ZAP_ALERT_RCE = "Remote OS Command Injection";

WAPITI_ALERT_XSS = "Cross Site Scripting"
WAPITI_ALERT_SQLI = "SQL Injection"
WAPITI_ALERT_SQLI_BLIND = "Blind SQL Injection"
WAPITI_ALERT_SQLI_SPRING_JDBC = "Spring JDBC Injection"
WAPITI_ALERT_LDAP = "LDAP Injection"
WAPITI_ALERT_PATH_TRAVERSAL = "Path Traversal"
WAPITI_ALERT_LFI = "local file disclosure vulnerability"
WAPITI_ALERT_LFI_CURRENT_FILE = "Possible source code disclosure" # I'm not actually sure if this is proper LFI
WAPITI_ALERT_RFI = "Remote inclusion vulnerability"
WAPITI_ALERT_RFI_DISCLOSURE = "Remote file disclosure vulnerability"
WAPITI_ALERT_RCE_COMMAND_EXEC = "Command execution"
WAPITI_ALERT_RCE_PHP_WARNING_EXEC = "Warning exec"  # exec is a PHP function, but used to execute OS commands
WAPITI_ALERT_PHP_WARNING_EVAL = "Warning eval()" # eval is a PHP function, used to execute PHP code
WAPITI_ALERT_PHP_EVALUATION = "PHP evaluation"
WAPITI_ALERT_PHP_PREG_REPLACE = "preg_replace injection"
WAPITI_ALERT_PHP_WARNING_ASSERT = "Warning assert"
WAPITI_ALERT_PHP_EVALUATION_WARNING = "Evaluation warning"

class VulnerabilityType(Enum):
    LFI = 1
    RFI = 2
    RCE = 3
    PHP = 4
    XSS = 5
    SQLI = 6
    LDAPI = 7


CRS_CONF_DICT = {
    VulnerabilityType.LFI: LFI_CONF,
    VulnerabilityType.RFI: RFI_CONF,
    VulnerabilityType.RCE: RCE_CONF,
    VulnerabilityType.PHP: PHP_CONF,
    VulnerabilityType.XSS: XSS_CONF,
    VulnerabilityType.SQLI: SQLI_CONF,
    VulnerabilityType.LDAPI: LDAPI_CONF
}

VULN_TAG_DICT = {
    VulnerabilityType.LFI: LFI_TAG,
    VulnerabilityType.RFI: RFI_TAG,
    VulnerabilityType.RCE: RCE_TAG,
    VulnerabilityType.PHP: PHP_TAG,
    VulnerabilityType.XSS: XSS_TAG,
    VulnerabilityType.SQLI: SQLI_TAG
}

ZAP_REPORT_ALERT_DICT = {
    ZAP_ALERT_LFI: [VulnerabilityType.LFI, VulnerabilityType.PHP],
    ZAP_ALERT_RFI: [VulnerabilityType.RFI, VulnerabilityType.PHP],
    ZAP_ALERT_RCE: [VulnerabilityType.RCE],
    ZAP_ALERT_PHP: [VulnerabilityType.PHP],
    ZAP_ALERT_XSS_PERS: [VulnerabilityType.XSS],
    ZAP_ALERT_XSS_REFL: [VulnerabilityType.XSS],
    ZAP_ALERT_SQLI: [VulnerabilityType.SQLI]
}

# If we need to differentiate between different vulnerabilities within a module
""" WAPITI_REPORT_ALERT_DICT = {
    WAPITI_ALERT_XSS: [VulnerabilityType.XSS],
    WAPITI_ALERT_SQLI: [VulnerabilityType.SQLI],
    WAPITI_ALERT_SQLI_BLIND: [VulnerabilityType.SQLI],
    WAPITI_ALERT_SQLI_SPRING_JDBC: [VulnerabilityType.SQLI],
    WAPITI_ALERT_LDAP: [VulnerabilityType.LDAPI],
    WAPITI_ALERT_LFI: [VulnerabilityType.LFI],
    WAPITI_ALERT_LFI_CURRENT_FILE: [VulnerabilityType.LFI],
    WAPITI_ALERT_RFI: [VulnerabilityType.RFI],
    WAPITI_ALERT_RFI_DISCLOSURE:  [VulnerabilityType.RFI],
    WAPITI_ALERT_RCE_COMMAND_EXEC: [VulnerabilityType.RCE],
    WAPITI_ALERT_RCE_PHP_WARNING_EXEC: [VulnerabilityType.RCE, VulnerabilityType.PHP],
    WAPITI_ALERT_PHP_WARNING_EVAL: [VulnerabilityType.PHP],
    WAPITI_ALERT_PHP_EVALUATION: [VulnerabilityType.PHP],
    WAPITI_ALERT_PHP_PREG_REPLACE: [VulnerabilityType.PHP],
    WAPITI_ALERT_PHP_WARNING_ASSERT: [VulnerabilityType.PHP],
    WAPITI_ALERT_PHP_EVALUATION_WARNING: [VulnerabilityType.PHP],
    WAPITI_ALERT_PATH_TRAVERSAL: [VulnerabilityType.LFI]
} """

WAPITI_REPORT_ALERT_DICT = {
    WAPITI_ALERT_XSS: [VulnerabilityType.XSS],
    WAPITI_ALERT_SQLI: [VulnerabilityType.SQLI],
    WAPITI_ALERT_SQLI_BLIND: [VulnerabilityType.SQLI],
    WAPITI_ALERT_LDAP: [VulnerabilityType.LDAPI],
    WAPITI_ALERT_PATH_TRAVERSAL: [VulnerabilityType.LFI, VulnerabilityType.PHP],
    WAPITI_ALERT_RCE_COMMAND_EXEC: [VulnerabilityType.RCE, VulnerabilityType.PHP]
}

WAPITI_REPORT_ALERT_DICT = {
    WAPITI_ALERT_XSS: [VulnerabilityType.XSS],
    WAPITI_ALERT_SQLI: [VulnerabilityType.SQLI],
    WAPITI_ALERT_SQLI_BLIND: [VulnerabilityType.SQLI],
    WAPITI_ALERT_SQLI_SPRING_JDBC: [VulnerabilityType.SQLI],
    WAPITI_ALERT_LDAP: [VulnerabilityType.LDAPI],
    WAPITI_ALERT_LFI: [VulnerabilityType.LFI],
    WAPITI_ALERT_LFI_CURRENT_FILE: [VulnerabilityType.LFI],
    WAPITI_ALERT_RFI: [VulnerabilityType.RFI],
    WAPITI_ALERT_RFI_DISCLOSURE:  [VulnerabilityType.RFI],
    WAPITI_ALERT_RCE_COMMAND_EXEC: [VulnerabilityType.RCE],
    WAPITI_ALERT_RCE_PHP_WARNING_EXEC: [VulnerabilityType.RCE, VulnerabilityType.PHP],
    WAPITI_ALERT_PHP_WARNING_EVAL: [VulnerabilityType.PHP],
    WAPITI_ALERT_PHP_EVALUATION: [VulnerabilityType.PHP],
    WAPITI_ALERT_PHP_PREG_REPLACE: [VulnerabilityType.PHP],
    WAPITI_ALERT_PHP_WARNING_ASSERT: [VulnerabilityType.PHP],
    WAPITI_ALERT_PHP_EVALUATION_WARNING: [VulnerabilityType.PHP],
    WAPITI_ALERT_PATH_TRAVERSAL: [VulnerabilityType.LFI]
}

METHOD_VARIABLE_DICT = {
    "GET": "ARGS_GET",
    "POST": "ARGS_POST"
}

# https://stackoverflow.com/questions/635483/what-is-the-best-way-to-implement-nested-dictionaries
class Vividict(dict):
    def __missing__(self, key):
        value = self[key] = type(self)() # retain local pointer to value
        return value                     # faster to return than dict lookup

def get_targets():
    return ['ARGS', 'ARGS_NAMES', 'REQUEST_COOKIES', 'REQUEST_COOKIES_NAMES', 'REQUEST_HEADERS', 
            'FILES', 'FILES_NAMES', 'PATH_INFO', 'QUERY_STRING', 'REQUEST_BODY', 'REQUEST_BASENAME',
            'REQUEST_FILENAME', 'XML', 'REQUEST_LINE', 'REQUEST_URI', 'REQUEST_URI_RAW']

    
def negate_targets(targets):
    return list(map(lambda target : '!' + target, targets))

def generate_virtual_patches(vulnerabilities, vuln_app_filename):
    print(f"Creating {vuln_app_filename}")

    with open(vuln_app_filename, 'w') as out_file:
        for location in vulnerabilities:
            out_file.write(generate_virtual_patch(location, vulnerabilities[location]))

def generate_virtual_patch(location, vulnerabilities):
        location_match_start_tag = f'<LocationMatch "^{location}$">'
        sec_default_actions = ['SecDefaultAction "phase:1,log,auditlog,pass"',
                               'SecDefaultAction "phase:2,log,auditlog,pass"']
        vuln_include_directives = [f'Include {CRS_CONF_DICT[vulnerability_type]}' for vulnerability_type in vulnerabilities]
        default_include_directives = [f'Include {BLOCKING_CONF}',
                                      f'Include {CORRELATION_CONF}']
        target_separator = ',\\\n\t' + (len('SecRuleUpdateTargetByTag "') * ' ')
        negated_targets = target_separator.join(negate_targets(get_targets()))
        sec_rules_remove_targets = [f'SecRuleUpdateTargetByTag "{VULN_TAG_DICT[vulnerability_type]}" "{negated_targets}"' \
                                   for vulnerability_type in vulnerabilities]
        sec_rule_remove_rules = []
        if VulnerabilityType.LDAPI in vulnerabilities:
            sec_rule_remove_rules = [f'SecRuleRemoveByTag "{LDAP_TAG}"']

        sec_rules_add_params = []
        for vulnerability_type in vulnerabilities:
            params = []
            for method in vulnerabilities[vulnerability_type]:
                if method in METHOD_VARIABLE_DICT:
                    params += [f'ARGS:{param}' for param in vulnerabilities[vulnerability_type][method]]
            params = list(set(params))   # Remove duplicates
            sec_rules_add_params.append(f'SecRuleUpdateTargetByTag "{VULN_TAG_DICT[vulnerability_type]}" "{",".join(params)}"')

        location_match_end_tag = '</LocationMatch>'

        return location_match_start_tag + '\n' + \
               '\t' + '\n\t'.join(sec_default_actions) + '\n\n' + \
               '\t' + '\n\t'.join(vuln_include_directives) + '\n\n' + \
               '\t' + '\n\t'.join(default_include_directives) + '\n\n' + \
               '\t' + '\n\n\t'.join(sec_rules_remove_targets) + '\n\n' + \
               '\t' + '\n\t'.join(sec_rules_add_params) + '\n\n' + \
               '\t' + '\n\t'.join(sec_rule_remove_rules) + '\n' + \
               location_match_end_tag + '\n\n'


def process_zap_report(report_path):
    vulnerabilities = None
    if report_path.endswith('.xml'):
        vulnerabilities = process_zap_xml_report(report_path)
    elif report_path.endswith('json'):
        vulnerabilities = process_zap_json_report(report_path)
    else:
        print('ERROR: Cannot process ZAP report (unsupported filetype)')

    return vulnerabilities

def process_zap_xml_report(report_path):
    zap_report_tree = ET.parse(report_path)
    zap_report_root = zap_report_tree.getroot()
    vulnerabilities = Vividict()

    for site in zap_report_root:
        alerts = site.find('alerts')
        for alert in alerts:
            name = alert.find('name').text
            if ZAP_REPORT_ALERT_DICT.get(name) is None: continue
            vulnerability_types = ZAP_REPORT_ALERT_DICT[name]

            instances = alert.find('instances')
            for instance in instances:
                method = instance.find('method').text
                if method not in ['GET', 'POST']: 
                    print(f'UNSUPPORTED METHOD: {method}. SKIPPING...')
                    continue

                uri = instance.find('uri')
                location = ''
                if uri is not None: 
                    location = urlparse(uri.text).path

                param_el = instance.find('param')
                param = ''
                if param_el is not None: 
                    param = param_el.text
                else:
                    print(f'NO PARAM DETECTED FOR {name.text} - {location}. SKIPPING...')
                    continue

                for vulnerability_type in vulnerability_types:
                        if not vulnerabilities[location][vulnerability_type][method]:
                            vulnerabilities[location][vulnerability_type][method] = [param]
                        else:
                            vulnerabilities[location][vulnerability_type][method] += [param]

    return vulnerabilities

def process_zap_json_report(report_path):
    print("ZAP JSON report currently unsupported")
    return None


def process_wapiti_report(report_path):
    vulnerabilities = None
    if report_path.endswith('.xml'):
        vulnerabilities = process_wapiti_xml_report(report_path)
    elif report_path.endswith('.json'):
        vulnerabilities = process_wapiti_json_report(report_path)
    else:
        print('ERROR: Cannot process wapiti report (unsupported filetype)')

    return vulnerabilities

def process_wapiti_xml_report(report_path):
    print("Wapiti XML report currently unsupported")
    return None


def contains_from_list(str_list, str):
    for el in str_list:
        if el in str: return el
    return None

def process_wapiti_json_report(report_path):
    vulnerabilities = Vividict()
    with open(report_path, 'r') as wapiti_report_file:
        wapiti_report = json.load(wapiti_report_file)
        vulnerabilities_json = wapiti_report['vulnerabilities']

        for vulnerability_name in vulnerabilities_json:
            if vulnerability_name not in WAPITI_REPORT_ALERT_DICT: continue

            for vulnerability in vulnerabilities_json[vulnerability_name]:
                method = vulnerability["method"]
                location = vulnerability["path"]
                parameter = vulnerability["parameter"]
                vulnerability_types = []
                if vulnerability_name == WAPITI_ALERT_SQLI:
                    if WAPITI_ALERT_LDAP in vulnerability['info']:
                        vulnerability_types = WAPITI_REPORT_ALERT_DICT[WAPITI_ALERT_LDAP]
                    else:
                        vulnerability_types = WAPITI_REPORT_ALERT_DICT[WAPITI_ALERT_SQLI]

                # If we differentiate amongst the different types of PHP/OS commands
                # elif vulnerability_name == WAPITI_ALERT_RCE_COMMAND_EXEC:
                #     new_vulnerability_name = contains_from_list([WAPITI_ALERT_RCE_COMMAND_EXEC, 
                #                                                  WAPITI_ALERT_RCE_PHP_WARNING_EXEC, 
                #                                                  WAPITI_ALERT_PHP_PREG_REPLACE, 
                #                                                  WAPITI_ALERT_PHP_WARNING_EVAL, 
                #                                                  WAPITI_ALERT_PHP_EVALUATION, 
                #                                                  WAPITI_ALERT_PHP_EVALUATION_WARNING, 
                #                                                  WAPITI_ALERT_PHP_WARNING_ASSERT], 
                #                                                  vulnerability['info'])
                #     if new_vulnerability_name is not None:
                #         vulnerability_types = WAPITI_REPORT_ALERT_DICT[new_vulnerability_name]

                # If we differentiate amongst the different types of lfi/rfi attacks
                # elif vulnerability_name == WAPITI_ALERT_PATH_TRAVERSAL:
                #     new_vulnerability_name = contains_from_list([WAPITI_ALERT_LFI,
                #                                                  WAPITI_ALERT_LFI_CURRENT_FILE,
                #                                                  WAPITI_ALERT_PATH_TRAVERSAL,
                #                                                  WAPITI_ALERT_RFI,
                #                                                  WAPITI_ALERT_RFI_DISCLOSURE], 
                #                                                  vulnerability['info'])
                #    if new_vulnerability_name is not None:
                #        vulnerability_types = WAPITI_REPORT_ALERT_DICT[new_vulnerability_name]

                else:
                    vulnerability_types = WAPITI_REPORT_ALERT_DICT[vulnerability_name]

                for vulnerability_type in vulnerability_types:
                    if not vulnerabilities[location][vulnerability_type][method]:
                        vulnerabilities[location][vulnerability_type][method] = [parameter]
                    else:
                        vulnerabilities[location][vulnerability_type][method] += [parameter]
    
    return vulnerabilities


def main():
    if len(sys.argv) != 4:
        print("python virtualpatcher.py <zap|wapiti> </path/to/report> <output_filename>")
        return
    
    scanner = sys.argv[1].lower()
    if scanner not in SUPPORTED_SCANNERS:
        print(f"Scanner {scanner} not recognized. Options: zap|wapiti")
        return
    
    report_path = sys.argv[2]
    if not os.path.exists(report_path):
        print(f"The specified path {report_path} does not exist")
        return

    vulnerabilities = None
    if scanner == "zap":
        vulnerabilities = process_zap_report(report_path)
    elif scanner == "wapiti":
        vulnerabilities = process_wapiti_report(report_path)
    
    if vulnerabilities is None:
        print("No vulnerabilities were found. Exiting...")
        return

    vuln_app_file_name = sys.argv[3]
    generate_virtual_patches(vulnerabilities, vuln_app_file_name)


if __name__ == "__main__":
    main()