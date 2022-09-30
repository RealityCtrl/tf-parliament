#!/usr/bin/env python
import argparse
import glob
import hcl2
import lark
import os
import re
import json
import parliament
import sys
import ast

statement_template = """{{
    "Effect": "{effect}",
    "Action": {actions}
    {resources_block}
}}"""

policy_template = """{{
    "Version": "2012-10-17",
    "Id": "123",
    "Statement": {iam_statements}
}}"""

field_mappings = [
   # {'tf_key': 'effect', 'iam_key': 'Effect', 'mock_value': 'Allow'},
    {'tf_key': 'actions', 'iam_key': 'Action', 'mock_value': '*'},
    {'tf_key': 'not_actions', 'iam_key': 'NotAction', 'mock_value': '*'},
    {'tf_key': 'resources', 'iam_key': 'Resource', 'mock_value': '*'},
    {'tf_key': 'not_resources', 'iam_key': 'NotResource', 'mock_value': '*'},
]


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def format_finding(finding):
    if isinstance(finding['finding'], list):
        for detail in finding['finding']:
            try:
                issue = detail.issue
                location = detail.location
                detail_print = detail.detail
                policy=finding['policy']
                formatted = f'{bcolors.WARNING}{issue}{bcolors.ENDC}\nPolicy:\n  {policy}{bcolors.ENDC}\nDetails:\n  {detail_print}\nLocation:\n  {location}'
                print(formatted)
            except AttributeError as ex:
                print(detail)
    else:
        print(finding['finding'])


def mock_iam_statement_from_tf(statement_data):
    # Create a mock IAM statement from a TF definition,
    # copying across only fields defined in the field_mappings
    # and replacing TF interpolations "${var.xxx}"
    # with mock vars for the field to pass validation
    mock_iam_statement = {}

    # In TF, effect is optional and defaults to 'Allow'
    try:
        mock_iam_statement['Effect'] = statement_data['effect']
    except KeyError:
        mock_iam_statement['Effect'] = 'Allow'
    for field in field_mappings:
        if statement_data.get(field['tf_key'], None):
            field_values = statement_data.get(field['tf_key'])
            if isinstance(field_values, list):
                if len(field_values) == 1 and field_values[0] == '*':
                    field_values = '*'
                else:
                    field_values = list(map(lambda x: re.sub('\${.*?}', field['mock_value'], x), field_values))
            elif isinstance(field_values, str) and field_values.startswith('${setunion'):
                """
                    For setunion functions we need to separate the elements being joined, process them and join them
                    We can also have lists being passed in a pure parameters.
                    Currently this code handle the format of setunion(["arn1", "arn2"], var.some_other_arns)
                    It needs updated to handle other formats and ordering of arrays and variables
                """
                #field_values.count('[')
                start = field_values.find('[')
                end = field_values.rfind(']')+1
                field_values_remainder = field_values[end:-1]
                field_values_remainder = field_values_remainder.split(',')
                field_values_remainder = list(map(lambda x: x.strip(), field_values_remainder))
                field_values_remainder = list(filter(lambda x: len(x) > 0, field_values_remainder))

                field_values_remainder = list(map(lambda x: re.sub('\${.*?}', field['mock_value'], x), field_values_remainder))
                field_values_remainder = list(map(lambda x: '*' if x.startswith('var.') else x, field_values_remainder))
                field_values_list_string = field_values[start: end]
                field_values_list = ast.literal_eval(field_values_list_string)
                field_values = list(map(lambda x: re.sub('\${.*?}', field['mock_value'], x), field_values_list))

                field_values += field_values_remainder
            else:
                field_values = re.sub('\${.*?}', field['mock_value'], field_values)
                field_values = list(map(lambda x: '*' if x.startswith('var.') else x, field_values))

            mock_iam_statement[field['iam_key']] = field_values
    return mock_iam_statement


def validate_file(filename):
    try:
        with(open(filename, 'r')) as file:
            tf = hcl2.load(file)
    except lark.exceptions.UnexpectedToken as e:
        return [parliament.finding.Finding("Failed to parse file", str(e), filename)]

    findings_output = []

    # Validate data.aws_iam_policy_document
    for policy_document in filter(lambda x: x.get('aws_iam_policy_document', None), tf.get('data', [])):
        iam_statements = []

        for policy_name, policy in policy_document['aws_iam_policy_document'].items():
            if 'statement' in policy:
                for statement_data in policy['statement']:
                    # Don't check assume role policies; these will have spurious findings for
                    # "Statement contains neither Resource nor NotResource"
                    actions = statement_data.get('actions')
                    assume_role = False
                    if isinstance(actions, list):
                        for action in actions:
                            if action == 'sts:AssumeRole' or action == 'sts:AssumeRoleWithSAML':
                                assume_role = True
                        if assume_role:
                            continue
                    elif actions == 'sts:AssumeRole' or actions == 'sts:AssumeRoleWithSAML':
                        continue

                    iam_statements.append(mock_iam_statement_from_tf(statement_data))

        policy_string = policy_template.format(iam_statements=json.dumps(iam_statements))

        policy_findings = parliament.analyze_policy_string(policy_string).findings
        if len(policy_findings) > 0:
            finding = {
                'policy': iam_statements,
                'finding': policy_findings
            }
            findings_output.append(finding)

    # Validate resource.aws_iam_policy
    for policy_resource in filter(lambda x: x.get('aws_iam_policy', None), tf.get('resource', [])):
        for policy_name, policy in policy_resource['aws_iam_policy'].items():
            try:
                policy_string = policy['policy'][0]
                policy_string = policy_string.replace('\\"', '"')
            except KeyError:
                continue
            policy_findings = parliament.analyze_policy_string(policy_string).findings
            if len(policy_findings) > 0:
                finding = {
                    'policy': policy_string,
                    'finding': policy_findings
                }
                findings_output.append(finding)
    return findings_output


if '__main__' == __name__:
    parser = argparse.ArgumentParser()
    parser.add_argument('filename_list', nargs='+')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help="Quiet mode - only print if policy errors")
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    args = parser.parse_args()

    # Bool to indicate if any findings, for all files - will be used for exit code
    findings_found = False

    for filename in args.filename_list:
        # If directory specified, scan all files in that dir
        if os.path.isdir(filename):
            filename = os.path.join(filename, '*')

        # Expand wildcards
        for filename in glob.glob(filename):
            # Only operate on .tf
            if not filename.endswith('.tf'):
                continue

            findings = validate_file(filename)
            if len(findings) > 0:
                print(f"{bcolors.FAIL}{filename}{bcolors.ENDC}")
                for f in findings:
                    format_finding(f)
                    findings_found = True
                print()
            elif args.verbose:
                print(f"{bcolors.OKGREEN}{filename} VALID{bcolors.ENDC}")

    # If we found any findings, in any files, exit code non-zero
    if findings_found:
        sys.exit(1)
    else:
        if not args.quiet:
            print(f"{bcolors.OKGREEN}No errors found{bcolors.ENDC}")
