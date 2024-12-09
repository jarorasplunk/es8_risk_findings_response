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

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=get_phase_id_1)

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

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["splunk"], callback=run_query_1_callback)

    return


@phantom.playbook_block()
def run_query_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1_callback() called")

    
    threat_object_type(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    threat_list(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["threat_object_type:custom_function_result.data.output", "==", "file_hash"],
            ["threat_object:custom_function_result.data.output", "!=", ""]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_virustotal_v3_identifier_reputation_analysis_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["threat_object_type:custom_function_result.data.output", "==", "process"],
            ["threat_object:custom_function_result.data.output", "!=", "run_query_1:action_result.data.*.threat_object_type"]
        ],
        name="filter_1:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        playbook_encoded_powershell_investigation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["threat_object_type:custom_function_result.data.output", "==", "ip"],
            ["threat_object:custom_function_result.data.output", "!=", ""]
        ],
        name="filter_1:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        playbook_virustotal_v3_identifier_reputation_analysis_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids and results for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["threat_object_type:custom_function_result.data.output", "==", "url"],
            ["threat_object:custom_function_result.data.output", "!=", ""]
        ],
        name="filter_1:condition_4",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        playbook_virustotal_v3_identifier_reputation_analysis_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    # collect filtered artifact ids and results for 'if' condition 5
    matched_artifacts_5, matched_results_5 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["threat_object_type:custom_function_result.data.output", "==", "domain"],
            ["threat_object:custom_function_result.data.output", "!=", ""]
        ],
        name="filter_1:condition_5",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        playbook_virustotal_v3_identifier_reputation_analysis_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_5, filtered_results=matched_results_5)

    return


@phantom.playbook_block()
def playbook_internal_host_winrm_investigate_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_internal_host_winrm_investigate_1() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_2:run_query_1:action_result.data.*.risk_object"])

    filtered_result_0_data___risk_object = [item[0] for item in filtered_result_0_data_filter_1]

    inputs = {
        "ip_or_hostname": filtered_result_0_data___risk_object,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/internal_host_winrm_investigate", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/internal_host_winrm_investigate", container=container, name="playbook_internal_host_winrm_investigate_1", callback=add_task_note_2, inputs=inputs)

    return


@phantom.playbook_block()
def get_phase_id_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_phase_id_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.name"])

    parameters = []

    # build parameters list for 'get_phase_id_1' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None and finding_data_item[1] is not None:
            parameters.append({
                "id": finding_data_item[0],
                "phase_name": "Investigate",
                "response_template_name": finding_data_item[1],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get phase id", parameters=parameters, name="get_phase_id_1", assets=["builtin_mc_connector"], callback=get_task_id_1)

    return


@phantom.playbook_block()
def get_task_id_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_task_id_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.name"])

    parameters = []

    # build parameters list for 'get_task_id_1' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None and finding_data_item[1] is not None:
            parameters.append({
                "id": finding_data_item[0],
                "task_name": "Investigate findings",
                "phase_name": "Investigate",
                "response_template_name": finding_data_item[1],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get task id", parameters=parameters, name="get_task_id_1", assets=["builtin_mc_connector"], callback=run_query_1)

    return


@phantom.playbook_block()
def add_task_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""{0}\n\n\n{1}\n\n""",
        parameters=[
            "playbook_virustotal_v3_identifier_reputation_analysis_1:playbook_output:observable",
            "playbook_virustotal_v3_identifier_reputation_analysis_1:playbook_output:markdown_report"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    playbook_virustotal_v3_identifier_reputation_analysis_1_output_observable = phantom.collect2(container=container, datapath=["playbook_virustotal_v3_identifier_reputation_analysis_1:playbook_output:observable"])
    playbook_virustotal_v3_identifier_reputation_analysis_1_output_markdown_report = phantom.collect2(container=container, datapath=["playbook_virustotal_v3_identifier_reputation_analysis_1:playbook_output:markdown_report"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for finding_data_item in finding_data:
        for playbook_virustotal_v3_identifier_reputation_analysis_1_output_observable_item in playbook_virustotal_v3_identifier_reputation_analysis_1_output_observable:
            for playbook_virustotal_v3_identifier_reputation_analysis_1_output_markdown_report_item in playbook_virustotal_v3_identifier_reputation_analysis_1_output_markdown_report:
                for get_task_id_1_result_item in get_task_id_1_result_data:
                    for get_phase_id_1_result_item in get_phase_id_1_result_data:
                        if finding_data_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and finding_data_item[1] is not None:
                            parameters.append({
                                "id": finding_data_item[0],
                                "title": "Identifier Activity Analysis:",
                                "content": content_formatted_string,
                                "task_id": get_task_id_1_result_item[0],
                                "phase_id": get_phase_id_1_result_item[0],
                                "response_plan_id": finding_data_item[1],
                            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def add_task_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""Host investigation launched, please check the diag files returned from the host.\n""",
        parameters=[])

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id"])

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None and content_formatted_string is not None:
            parameters.append({
                "id": finding_data_item[0],
                "title": "Windows Host investigation:",
                "content": content_formatted_string,
                "task_id": "",
                "phase_id": "",
                "response_plan_id": "",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_2", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def playbook_encoded_powershell_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_encoded_powershell_investigation_1() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_3:run_query_1:action_result.data.*.threat_object"])

    filtered_result_0_data___threat_object = [item[0] for item in filtered_result_0_data_filter_1]

    inputs = {
        "powershell_process": filtered_result_0_data___threat_object,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/encoded_powershell_investigation", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/encoded_powershell_investigation", container=container, name="playbook_encoded_powershell_investigation_1", callback=add_task_note_3, inputs=inputs)

    return


@phantom.playbook_block()
def add_task_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""Malicious Powershell Analysis:  {0}\n""",
        parameters=[
            "playbook_encoded_powershell_investigation_1:playbook_output:note_title"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    playbook_encoded_powershell_investigation_1_output_note_title = phantom.collect2(container=container, datapath=["playbook_encoded_powershell_investigation_1:playbook_output:note_title"])
    playbook_encoded_powershell_investigation_1_output_note_content = phantom.collect2(container=container, datapath=["playbook_encoded_powershell_investigation_1:playbook_output:note_content"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for finding_data_item in finding_data:
        for playbook_encoded_powershell_investigation_1_output_note_title_item in playbook_encoded_powershell_investigation_1_output_note_title:
            for playbook_encoded_powershell_investigation_1_output_note_content_item in playbook_encoded_powershell_investigation_1_output_note_content:
                for get_task_id_1_result_item in get_task_id_1_result_data:
                    for get_phase_id_1_result_item in get_phase_id_1_result_data:
                        if finding_data_item[0] is not None and title_formatted_string is not None and playbook_encoded_powershell_investigation_1_output_note_content_item[0] is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and finding_data_item[1] is not None:
                            parameters.append({
                                "id": finding_data_item[0],
                                "title": title_formatted_string,
                                "content": playbook_encoded_powershell_investigation_1_output_note_content_item[0],
                                "task_id": get_task_id_1_result_item[0],
                                "phase_id": get_phase_id_1_result_item[0],
                                "response_plan_id": finding_data_item[1],
                            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_3", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def playbook_virustotal_v3_identifier_reputation_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_virustotal_v3_identifier_reputation_analysis_1() called")

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_4:threat_object:custom_function_result.data.output"])
    filtered_cf_result_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_5:threat_object:custom_function_result.data.output"])
    filtered_cf_result_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_3:threat_object:custom_function_result.data.output"])
    filtered_cf_result_3 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:threat_object:custom_function_result.data.output"])

    filtered_cf_result_0_data_output = [item[0] for item in filtered_cf_result_0]
    filtered_cf_result_1_data_output = [item[0] for item in filtered_cf_result_1]
    filtered_cf_result_2_data_output = [item[0] for item in filtered_cf_result_2]
    filtered_cf_result_3_data_output = [item[0] for item in filtered_cf_result_3]

    inputs = {
        "url": filtered_cf_result_0_data_output,
        "domain": filtered_cf_result_1_data_output,
        "ip": filtered_cf_result_2_data_output,
        "file_hash": filtered_cf_result_3_data_output,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/VirusTotal_v3_Identifier_Reputation_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/VirusTotal_v3_Identifier_Reputation_Analysis", container=container, name="playbook_virustotal_v3_identifier_reputation_analysis_1", callback=add_task_note_1, inputs=inputs)

    return


@phantom.playbook_block()
def hash_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("hash_list() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:run_query_1:action_result.data.*.threat_object"])

    parameters = []

    # build parameters list for 'hash_list' call
    for filtered_result_0_item_filter_1 in filtered_result_0_data_filter_1:
        parameters.append({
            "input_list": filtered_result_0_item_filter_1[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="hash_list")

    return


@phantom.playbook_block()
def ip_and_domain_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_and_domain_list() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_4:run_query_1:action_result.data.*.threat_object"])

    parameters = []

    # build parameters list for 'ip_and_domain_list' call
    for filtered_result_0_item_filter_1 in filtered_result_0_data_filter_1:
        parameters.append({
            "input_list": filtered_result_0_item_filter_1[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="ip_and_domain_list")

    return


@phantom.playbook_block()
def url_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_list() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_5:run_query_1:action_result.data.*.threat_object"])

    parameters = []

    # build parameters list for 'url_list' call
    for filtered_result_0_item_filter_1 in filtered_result_0_data_filter_1:
        parameters.append({
            "input_list": filtered_result_0_item_filter_1[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="url_list")

    return


@phantom.playbook_block()
def threat_object_type(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threat_object_type() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.threat_object_type","run_query_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'threat_object_type' call
    for run_query_1_result_item in run_query_1_result_data:
        parameters.append({
            "input_list": run_query_1_result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="threat_object_type", callback=threat_object)

    return


@phantom.playbook_block()
def threat_object(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threat_object() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.threat_object","run_query_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'threat_object' call
    for run_query_1_result_item in run_query_1_result_data:
        parameters.append({
            "input_list": run_query_1_result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="threat_object")

    return


@phantom.playbook_block()
def debug_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_6() called")

    threat_object_type__result = phantom.collect2(container=container, datapath=["threat_object_type:custom_function_result.data.output"])
    threat_object__result = phantom.collect2(container=container, datapath=["threat_object:custom_function_result.data.output"])

    threat_object_type_data_output = [item[0] for item in threat_object_type__result]
    threat_object_data_output = [item[0] for item in threat_object__result]

    parameters = []

    parameters.append({
        "input_1": threat_object_type_data_output,
        "input_2": threat_object_data_output,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_6")

    return


@phantom.playbook_block()
def list_zip_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_zip_7() called")

    threat_object_type__result = phantom.collect2(container=container, datapath=["threat_object_type:custom_function_result.data.output"])
    threat_object__result = phantom.collect2(container=container, datapath=["threat_object:custom_function_result.data.output"])

    threat_object_type_data_output = [item[0] for item in threat_object_type__result]
    threat_object_data_output = [item[0] for item in threat_object__result]

    parameters = []

    parameters.append({
        "zip_type": None,
        "pad_values": None,
        "input_1": threat_object_type_data_output,
        "input_2": threat_object_data_output,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_zip", parameters=parameters, name="list_zip_7", callback=debug_8)

    return


@phantom.playbook_block()
def debug_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_8() called")

    list_zip_7__result = phantom.collect2(container=container, datapath=["list_zip_7:custom_function_result.data.input_1","list_zip_7:custom_function_result.data.input_2","list_zip_7:custom_function_result.success","list_zip_7:custom_function_result.message"])

    list_zip_7_data_input_1 = [item[0] for item in list_zip_7__result]
    list_zip_7_data_input_2 = [item[1] for item in list_zip_7__result]
    list_zip_7_success = [item[2] for item in list_zip_7__result]
    list_zip_7_message = [item[3] for item in list_zip_7__result]

    parameters = []

    parameters.append({
        "input_1": list_zip_7_data_input_1,
        "input_2": list_zip_7_data_input_2,
        "input_3": list_zip_7_success,
        "input_4": list_zip_7_message,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_8")

    return


@phantom.playbook_block()
def threat_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threat_list() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.threat_object_type","run_query_1:action_result.data.*.threat_object"], action_results=results)

    run_query_1_result_item_0 = [item[0] for item in run_query_1_result_data]
    run_query_1_result_item_1 = [item[1] for item in run_query_1_result_data]

    threat_list__threat_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    threat_list__threat_list = []
    
    for i in range(len(run_query_1_result_item_0)):
        threat_list_tuple = []
        threat_list_tuple.append(run_query_1_result_item_0[i])
        threat_list_tuple.append(run_query_1_result_item_1[i])
        threat_list__threat_list.append(threat_list_tuple)
            
    phantom.debug(threat_list__threat_list)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="threat_list:threat_list", value=json.dumps(threat_list__threat_list))

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