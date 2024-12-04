"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_finding_or_investigation_1' block
    get_finding_or_investigation_1(container=container)

    return

@phantom.playbook_block()
def get_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id"])

    parameters = []

    # build parameters list for 'get_finding_or_investigation_1' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None:
            parameters.append({
                "id": finding_data_item[0],
                "finding_time": "",
                "map_consolidated_findings": 1,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=run_query_1)

    return


@phantom.playbook_block()
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template=""" datamodel:Risk \n| search normalized_risk_object=\"{0}\" risk_object_type=\"{3}\" \n| where _time>={1} AND _time<={2}  | eval risk_event_id = if(isnull(risk_event_id), index + \"_\" + _cd + \"_\" + splunk_server, risk_event_id) | eventstats count by risk_event_id | where count < 2 \n| eval risk_message=coalesce(risk_message,source) \n| eval threat_zip = mvzip(threat_object, threat_object_type) \n| rename annotations.mitre_attack.mitre_technique_id as mitre_technique_id annotations.mitre_attack.mitre_tactic as mitre_tactic annotations.mitre_attack.mitre_technique as mitre_technique \n| fields - annotations* orig_sid orig_rid risk_factor* splunk_server host sourcetype tag threat_object* \n| stats list(risk_event_id) as risk_event_ids list(_time) as original_timestamps count as _event_count sum(calculated_risk_score) as _total_risk_score earliest(_time) as earliest latest(_time) as latest values(*) as * by search_name risk_message \n| where NOT (match(source, \"Splunk\\sSOAR\") AND _total_risk_score<=0) \n| fields mitre* _event_count _total_risk_score original_timestamps threat_zip risk_event_ids threat_object\n    [| rest /services/datamodel/model \n    | search eai:acl.app IN (Splunk_SA_CIM, SA-IdentityManagement, SA-NetworkProtection, SA-ThreatIntelligence, DA-ESS-ThreatIntelligence) \n    | fields description \n    | spath input=description path=objects{{}}.fields{{}}.fieldName \n    | spath input=description path=objects{{}}.calculations{{}}.outputFields{{}}.fieldName \n    | eval fieldNames=mvappend('objects{{}}.fields{{}}.fieldName', 'objects{{}}.calculations{{}}.outputFields{{}}.fieldName') \n    | stats values(fieldNames) as fieldNames \n    | mvexpand fieldNames \n    | regex fieldNames=\"^[_a-z]+$\" \n    | stats values(fieldNames) as search] \n| sort + latest \n| `uitime(earliest)` \n| `uitime(latest)` \n| eval _time=latest \n| rex field=threat_zip \"(?<threat_object>.*)\\,(?<threat_object_type>.*)\" \n| fields - threat_zip\n""",
        parameters=[
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_min_time",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_max_time",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_min_time","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_max_time","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'run_query_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "| from",
                "end_time": "now",
                "start_time": "-365d",
                "search_mode": "verbose",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["splunk"], callback=filter_1)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["run_query_1:action_result.data.*threat_object_type", "in", "ip,hash,url,domain"]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:run_query_1:action_result.data.*.threat_object"])

    filtered_result_0_data___threat_object = [item[0] for item in filtered_result_0_data_filter_1]

    parameters = []

    parameters.append({
        "input_1": filtered_result_0_data___threat_object,
        "input_2": None,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return