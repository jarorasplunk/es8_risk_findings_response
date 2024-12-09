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

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["splunk"], callback=filter_1)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["url", "in", "run_query_1:action_result.data.*.threat_object_type"],
            ["file", "in", "run_query_1:action_result.data.*.threat_object_type"],
            ["hash", "in", "run_query_1:action_result.data.*.threat_object_type"],
            ["domain", "in", "run_query_1:action_result.data.*.threat_object_type"],
            ["ip", "in", "run_query_1:action_result.data.*.threat_object_type"]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_splunk_identifier_activity_analysis_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["run_query_1:action_result.data.*.threat_object_type", "==", "process"],
            ["windows", "in", "run_query_1:action_result.data.*.risk_object_category"]
        ],
        name="filter_1:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        playbook_internal_host_winrm_investigate_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["process", "in", "run_query_1:action_result.data.*.threat_object_type"],
            ["file_hash", "in", "run_query_1:action_result.data.*.threat_object_type"],
            ["hash", "in", "run_query_1:action_result.data.*.threat_object_type"]
        ],
        name="filter_1:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        playbook_encoded_powershell_investigation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return


@phantom.playbook_block()
def playbook_splunk_identifier_activity_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_splunk_identifier_activity_analysis_1() called")

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_3:run_query_1:action_result.data.*.threat_object"])

    filtered_result_0_data___threat_object = [item[0] for item in filtered_result_0_data_filter_1]

    domain_file_url_ip_combined_value = phantom.concatenate(filtered_result_0_data___threat_object, dedup=True)

    inputs = {
        "ip": domain_file_url_ip_combined_value,
        "url": domain_file_url_ip_combined_value,
        "file": domain_file_url_ip_combined_value,
        "domain": domain_file_url_ip_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Splunk_Identifier_Activity_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Splunk_Identifier_Activity_Analysis", container=container, name="playbook_splunk_identifier_activity_analysis_1", callback=add_task_note_1, inputs=inputs)

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
            "playbook_splunk_identifier_activity_analysis_1:playbook_output:observable",
            "playbook_splunk_identifier_activity_analysis_1:playbook_output:markdown_report"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    playbook_splunk_identifier_activity_analysis_1_output_observable = phantom.collect2(container=container, datapath=["playbook_splunk_identifier_activity_analysis_1:playbook_output:observable"])
    playbook_splunk_identifier_activity_analysis_1_output_markdown_report = phantom.collect2(container=container, datapath=["playbook_splunk_identifier_activity_analysis_1:playbook_output:markdown_report"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for finding_data_item in finding_data:
        for playbook_splunk_identifier_activity_analysis_1_output_observable_item in playbook_splunk_identifier_activity_analysis_1_output_observable:
            for playbook_splunk_identifier_activity_analysis_1_output_markdown_report_item in playbook_splunk_identifier_activity_analysis_1_output_markdown_report:
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