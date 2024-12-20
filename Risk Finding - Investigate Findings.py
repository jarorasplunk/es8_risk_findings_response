"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'refresh_finding_or_investigation_1' block
    refresh_finding_or_investigation_1(container=container)

    return

@phantom.playbook_block()
def get_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_finding_or_investigation_1' call
    for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
        if refresh_finding_or_investigation_1_result_item[0] is not None:
            parameters.append({
                "id": refresh_finding_or_investigation_1_result_item[0],
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

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["splunk"], callback=threat_list)

    return


@phantom.playbook_block()
def threat_indicator_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threat_indicator_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["file_hash", "in", "threat_list_items:custom_function_result.data.output"]
        ],
        name="threat_indicator_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        threat_indicator_values(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["process", "in", "threat_list_items:custom_function_result.data.output"]
        ],
        name="threat_indicator_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        threat_indicator_values(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["ip", "in", "threat_list_items:custom_function_result.data.output"]
        ],
        name="threat_indicator_filter:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        threat_indicator_values(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids and results for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["url", "in", "threat_list_items:custom_function_result.data.output"]
        ],
        name="threat_indicator_filter:condition_4",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        threat_indicator_values(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    # collect filtered artifact ids and results for 'if' condition 5
    matched_artifacts_5, matched_results_5 = phantom.condition(
        container=container,
        conditions=[
            ["domain", "in", "threat_list_items:custom_function_result.data.output"]
        ],
        name="threat_indicator_filter:condition_5",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        threat_indicator_values(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_5, filtered_results=matched_results_5)

    return


@phantom.playbook_block()
def get_phase_id_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_phase_id_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.data.*.data.response_plans.*.name","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_phase_id_1' call
    for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
        if refresh_finding_or_investigation_1_result_item[0] is not None and refresh_finding_or_investigation_1_result_item[1] is not None:
            parameters.append({
                "id": refresh_finding_or_investigation_1_result_item[0],
                "phase_name": "Investigate",
                "response_template_name": refresh_finding_or_investigation_1_result_item[1],
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

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.data.*.data.response_plans.*.name","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_task_id_1' call
    for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
        if refresh_finding_or_investigation_1_result_item[0] is not None and refresh_finding_or_investigation_1_result_item[1] is not None:
            parameters.append({
                "id": refresh_finding_or_investigation_1_result_item[0],
                "task_name": "Investigate findings",
                "phase_name": "Investigate",
                "response_template_name": refresh_finding_or_investigation_1_result_item[1],
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
        template="""## Observable JSON:\n\n{0}\n\n\n\n\n{1}\n\n""",
        parameters=[
            "playbook_virustotal_v3_identifier_reputation_analysis_1:playbook_output:observable",
            "playbook_virustotal_v3_identifier_reputation_analysis_1:playbook_output:markdown_report"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    playbook_virustotal_v3_identifier_reputation_analysis_1_output_observable = phantom.collect2(container=container, datapath=["playbook_virustotal_v3_identifier_reputation_analysis_1:playbook_output:observable"])
    playbook_virustotal_v3_identifier_reputation_analysis_1_output_markdown_report = phantom.collect2(container=container, datapath=["playbook_virustotal_v3_identifier_reputation_analysis_1:playbook_output:markdown_report"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for playbook_virustotal_v3_identifier_reputation_analysis_1_output_observable_item in playbook_virustotal_v3_identifier_reputation_analysis_1_output_observable:
            for playbook_virustotal_v3_identifier_reputation_analysis_1_output_markdown_report_item in playbook_virustotal_v3_identifier_reputation_analysis_1_output_markdown_report:
                for get_task_id_1_result_item in get_task_id_1_result_data:
                    for get_phase_id_1_result_item in get_phase_id_1_result_data:
                        if get_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                            parameters.append({
                                "id": get_finding_or_investigation_1_result_item[0],
                                "title": "Identifier Activity Analysis from Virustotal:",
                                "content": content_formatted_string,
                                "task_id": get_task_id_1_result_item[0],
                                "phase_id": get_phase_id_1_result_item[0],
                                "response_plan_id": get_finding_or_investigation_1_result_item[1],
                            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_1", assets=["builtin_mc_connector"], callback=splunk_attack_analyzer_dynamic_analysis)

    return


@phantom.playbook_block()
def playbook_encoded_powershell_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_encoded_powershell_investigation_1() called")

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:route_investigation_playbooks:condition_2:process:custom_function_result.data.output"])

    filtered_cf_result_0_data_output = [item[0] for item in filtered_cf_result_0]

    inputs = {
        "powershell_process": filtered_cf_result_0_data_output,
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

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    playbook_encoded_powershell_investigation_1_output_note_title = phantom.collect2(container=container, datapath=["playbook_encoded_powershell_investigation_1:playbook_output:note_title"])
    playbook_encoded_powershell_investigation_1_output_note_content = phantom.collect2(container=container, datapath=["playbook_encoded_powershell_investigation_1:playbook_output:note_content"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for playbook_encoded_powershell_investigation_1_output_note_title_item in playbook_encoded_powershell_investigation_1_output_note_title:
            for playbook_encoded_powershell_investigation_1_output_note_content_item in playbook_encoded_powershell_investigation_1_output_note_content:
                for get_task_id_1_result_item in get_task_id_1_result_data:
                    for get_phase_id_1_result_item in get_phase_id_1_result_data:
                        if get_finding_or_investigation_1_result_item[0] is not None and title_formatted_string is not None and playbook_encoded_powershell_investigation_1_output_note_content_item[0] is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                            parameters.append({
                                "id": get_finding_or_investigation_1_result_item[0],
                                "title": title_formatted_string,
                                "content": playbook_encoded_powershell_investigation_1_output_note_content_item[0],
                                "task_id": get_task_id_1_result_item[0],
                                "phase_id": get_phase_id_1_result_item[0],
                                "response_plan_id": get_finding_or_investigation_1_result_item[1],
                            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_3", assets=["builtin_mc_connector"], callback=join_update_task_in_current_phase_1)

    return


@phantom.playbook_block()
def playbook_virustotal_v3_identifier_reputation_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_virustotal_v3_identifier_reputation_analysis_1() called")

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:route_investigation_playbooks:condition_3:ip:custom_function_result.data.output"])
    filtered_cf_result_1 = phantom.collect2(container=container, datapath=["filtered-data:route_investigation_playbooks:condition_4:url:custom_function_result.data.output"])
    filtered_cf_result_2 = phantom.collect2(container=container, datapath=["filtered-data:route_investigation_playbooks:condition_5:domain:custom_function_result.data.output"])
    filtered_cf_result_3 = phantom.collect2(container=container, datapath=["filtered-data:route_investigation_playbooks:condition_1:file_hash:custom_function_result.data.output"])

    filtered_cf_result_0_data_output = [item[0] for item in filtered_cf_result_0]
    filtered_cf_result_1_data_output = [item[0] for item in filtered_cf_result_1]
    filtered_cf_result_2_data_output = [item[0] for item in filtered_cf_result_2]
    filtered_cf_result_3_data_output = [item[0] for item in filtered_cf_result_3]

    inputs = {
        "ip": filtered_cf_result_0_data_output,
        "url": filtered_cf_result_1_data_output,
        "domain": filtered_cf_result_2_data_output,
        "file_hash": filtered_cf_result_3_data_output,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "es8_risk_findings_response/VirusTotal_v3_Identifier_Reputation_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("es8_risk_findings_response/VirusTotal_v3_Identifier_Reputation_Analysis", container=container, name="playbook_virustotal_v3_identifier_reputation_analysis_1", callback=add_task_note_1, inputs=inputs)

    return


@phantom.playbook_block()
def threat_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threat_list() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.threat_object_type","run_query_1:action_result.data.*.threat_object"], action_results=results)

    run_query_1_result_item_0 = [item[0] for item in run_query_1_result_data]
    run_query_1_result_item_1 = [item[1] for item in run_query_1_result_data]

    threat_list__threat_list = None
    threat_list__file_hash = None
    threat_list__ip = None
    threat_list__url = None
    threat_list__domain = None
    threat_list__process = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    

    def is_domain_format(value):
        # Check if it contains '.' but is not in IP address format
        parts = value.split('.')
        return len(parts) > 1 and not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    
    # Result lists
    threat_object = []
    threat_object_type = []
    
    finding_threat_objects__threat_object = []
    finding_threat_objects__threat_object_type = []

    result = []
    threat_list__threat_list = []
    # Iterate over the lists
    for item1, item2 in zip(run_query_1_result_item_1, run_query_1_result_item_0):
        if item1 is not None and item2 is not None:
            if isinstance(item1, list) and isinstance(item2, list):
                # If both items are lists, pair their elements individually
                for sub_item1, sub_item2 in zip(item1, item2):
                    threat_object.append(sub_item1)
                    threat_object_type.append(sub_item2)
            else:
                # Otherwise, pair the elements directly
                threat_object.append(item1)
                threat_object_type.append(item2)
    phantom.debug("First iteration of items")
    phantom.debug("threat_object")
    phantom.debug(threat_object)
    phantom.debug("threat_object_type")
    phantom.debug(threat_object_type)
    
    # Iterate through both lists and remove None values and duplicates
    seen = set()
    for item1, item2 in zip(threat_object, threat_object_type):
        if item1 is not None and item2 is not None:
            phantom.debug(item1)
            is_url = item1.startswith("http://") or item1.startswith("https://")
            is_domain = not is_url and is_domain_format(item1)
            if item2 == "other":
                if is_url:
                    item2 = "url"
                elif is_domain:
                    item2 = "domain"
            pair = (item1, item2)
            if pair not in seen:
                finding_threat_objects__threat_object.append(item1)
                finding_threat_objects__threat_object_type.append(item2)
                seen.add(pair)
    phantom.debug("Second iteration and normalisation")
    phantom.debug("finding_threat_objects__threat_object")
    phantom.debug(finding_threat_objects__threat_object)
    phantom.debug("finding_threat_objects__threat_object_type")
    phantom.debug(finding_threat_objects__threat_object_type)
    
    

    threat_list__file_hash = []
    threat_list__ip = []
    threat_list__url = []
    threat_list__domain = []
    threat_list__process = []
    
    # Result list
    result = []
    threat_list__threat_list = []
    # Iterate over the lists
    for item1, item2 in zip(finding_threat_objects__threat_object, finding_threat_objects__threat_object_type):
        phantom.debug("item1 in final list")
        phantom.debug(item1)
        phantom.debug("item2 in final list")
        phantom.debug(item2)
        if 'file_hash' in item2 or 'hash' in item2:
            threat_list__file_hash.append(item1)
        if 'ip' in item2:
            threat_list__ip.append(item1)
        if 'domain' in item2:
            threat_list__domain.append(item1)
        if 'url' in item2:
            threat_list__url.append(item1)
        if 'process' in item2:
            threat_list__process.append(item1)

    phantom.debug(threat_list__file_hash)
    phantom.debug(threat_list__ip)
    phantom.debug(threat_list__url)
    phantom.debug(threat_list__domain)
    phantom.debug(threat_list__process)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="threat_list:threat_list", value=json.dumps(threat_list__threat_list))
    phantom.save_run_data(key="threat_list:file_hash", value=json.dumps(threat_list__file_hash))
    phantom.save_run_data(key="threat_list:ip", value=json.dumps(threat_list__ip))
    phantom.save_run_data(key="threat_list:url", value=json.dumps(threat_list__url))
    phantom.save_run_data(key="threat_list:domain", value=json.dumps(threat_list__domain))
    phantom.save_run_data(key="threat_list:process", value=json.dumps(threat_list__process))

    domain(container=container)
    ip(container=container)
    file_hash(container=container)
    url(container=container)
    process(container=container)

    return


@phantom.playbook_block()
def threat_list_items(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threat_list_items() called")

    threat_list__threat_list = json.loads(_ if (_ := phantom.get_run_data(key="threat_list:threat_list")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": threat_list__threat_list,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []

    parameters.append({
        "input_list": threat_list__threat_list,
    })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="threat_list_items", callback=threat_indicator_filter)

    return


@phantom.playbook_block()
def threat_indicator_values(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threat_indicator_values() called")

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:threat_indicator_filter:condition_1:threat_list_items:custom_function_result.data.output"])
    filtered_cf_result_1 = phantom.collect2(container=container, datapath=["filtered-data:threat_indicator_filter:condition_2:threat_list_items:custom_function_result.data.output"])
    filtered_cf_result_2 = phantom.collect2(container=container, datapath=["filtered-data:threat_indicator_filter:condition_3:threat_list_items:custom_function_result.data.output"])
    filtered_cf_result_3 = phantom.collect2(container=container, datapath=["filtered-data:threat_indicator_filter:condition_4:threat_list_items:custom_function_result.data.output"])
    filtered_cf_result_4 = phantom.collect2(container=container, datapath=["filtered-data:threat_indicator_filter:condition_5:threat_list_items:custom_function_result.data.output"])

    filtered_cf_result_0_data_output = [item[0] for item in filtered_cf_result_0]
    filtered_cf_result_1_data_output = [item[0] for item in filtered_cf_result_1]
    filtered_cf_result_2_data_output = [item[0] for item in filtered_cf_result_2]
    filtered_cf_result_3_data_output = [item[0] for item in filtered_cf_result_3]
    filtered_cf_result_4_data_output = [item[0] for item in filtered_cf_result_4]

    threat_indicator_values__threat_indicator_hash = None
    threat_indicator_values__threat_indicator_ip = None
    threat_indicator_values__threat_indicator_domain = None
    threat_indicator_values__threat_indicator_url = None
    threat_indicator_values__threat_indicator_process = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import re
    
    threat_indicator_values__threat_indicator_hash = []
    threat_indicator_values__threat_indicator_ip = []
    threat_indicator_values__threat_indicator_domain = []
    threat_indicator_values__threat_indicator_url = []
    threat_indicator_values__threat_indicator_process = []
    
    if filtered_cf_result_0_data_output:
        threat_indicator_values__threat_indicator_hash.append(filtered_cf_result_0_data_output[0][1])
    else:
        threat_indicator_values__threat_indicator_hash.append(None)
        
    if filtered_cf_result_1_data_output:
        if '"' in filtered_cf_result_1_data_output[0][1]:
            escaped_process = re.sub(r'"', r'\"', filtered_cf_result_1_data_output[0][1])
            threat_indicator_values__threat_indicator_process.append(escaped_process)
        else:
            threat_indicator_values__threat_indicator_process.append(filtered_cf_result_1_data_output[0][1])
    else:
        threat_indicator_values__threat_indicator_process.append(None)
    
    if filtered_cf_result_2_data_output:
        threat_indicator_values__threat_indicator_ip.append(filtered_cf_result_2_data_output[0][1])
    else:
        threat_indicator_values__threat_indicator_ip.append(None)

    if filtered_cf_result_3_data_output:
        threat_indicator_values__threat_indicator_url.append(filtered_cf_result_3_data_output[0][1])
    else:
        threat_indicator_values__threat_indicator_url.append(None)

    if filtered_cf_result_4_data_output:
        threat_indicator_values__threat_indicator_domain.append(filtered_cf_result_4_data_output[0][1])
    else:
        threat_indicator_values__threat_indicator_domain.append(None)
    
    phantom.debug(threat_indicator_values__threat_indicator_hash)
    phantom.debug(threat_indicator_values__threat_indicator_process)
    phantom.debug(threat_indicator_values__threat_indicator_ip)
    phantom.debug(threat_indicator_values__threat_indicator_url)
    phantom.debug(threat_indicator_values__threat_indicator_domain)
    
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="threat_indicator_values:threat_indicator_hash", value=json.dumps(threat_indicator_values__threat_indicator_hash))
    phantom.save_run_data(key="threat_indicator_values:threat_indicator_ip", value=json.dumps(threat_indicator_values__threat_indicator_ip))
    phantom.save_run_data(key="threat_indicator_values:threat_indicator_domain", value=json.dumps(threat_indicator_values__threat_indicator_domain))
    phantom.save_run_data(key="threat_indicator_values:threat_indicator_url", value=json.dumps(threat_indicator_values__threat_indicator_url))
    phantom.save_run_data(key="threat_indicator_values:threat_indicator_process", value=json.dumps(threat_indicator_values__threat_indicator_process))

    return


@phantom.playbook_block()
def join_route_investigation_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_route_investigation_playbooks() called")

    if phantom.completed(custom_function_names=["ip", "file_hash", "domain", "url", "process"]):
        # call connected block "route_investigation_playbooks"
        route_investigation_playbooks(container=container, handle=handle)

    return


@phantom.playbook_block()
def route_investigation_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("route_investigation_playbooks() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["file_hash:custom_function_result.data.output", "!=", None]
        ],
        name="route_investigation_playbooks:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_virustotal_v3_identifier_reputation_analysis_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["process:custom_function_result.data.output", "!=", None]
        ],
        name="route_investigation_playbooks:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        playbook_encoded_powershell_investigation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["ip:custom_function_result.data.output", "!=", None]
        ],
        name="route_investigation_playbooks:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        playbook_virustotal_v3_identifier_reputation_analysis_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids and results for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["url:custom_function_result.data.output", "!=", None]
        ],
        name="route_investigation_playbooks:condition_4",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        playbook_virustotal_v3_identifier_reputation_analysis_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    # collect filtered artifact ids and results for 'if' condition 5
    matched_artifacts_5, matched_results_5 = phantom.condition(
        container=container,
        conditions=[
            ["domain:custom_function_result.data.output", "!=", None]
        ],
        name="route_investigation_playbooks:condition_5",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        playbook_virustotal_v3_identifier_reputation_analysis_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_5, filtered_results=matched_results_5)

    return


@phantom.playbook_block()
def ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip() called")

    threat_list__ip = json.loads(_ if (_ := phantom.get_run_data(key="threat_list:ip")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": threat_list__ip,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="ip", callback=join_route_investigation_playbooks)

    return


@phantom.playbook_block()
def file_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("file_hash() called")

    threat_list__file_hash = json.loads(_ if (_ := phantom.get_run_data(key="threat_list:file_hash")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": threat_list__file_hash,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="file_hash", callback=join_route_investigation_playbooks)

    return


@phantom.playbook_block()
def domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("domain() called")

    threat_list__domain = json.loads(_ if (_ := phantom.get_run_data(key="threat_list:domain")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": threat_list__domain,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="domain", callback=join_route_investigation_playbooks)

    return


@phantom.playbook_block()
def url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url() called")

    threat_list__url = json.loads(_ if (_ := phantom.get_run_data(key="threat_list:url")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": threat_list__url,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="url", callback=join_route_investigation_playbooks)

    return


@phantom.playbook_block()
def process(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("process() called")

    threat_list__process = json.loads(_ if (_ := phantom.get_run_data(key="threat_list:process")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": threat_list__process,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="process", callback=join_route_investigation_playbooks)

    return


@phantom.playbook_block()
def splunk_attack_analyzer_dynamic_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("splunk_attack_analyzer_dynamic_analysis() called")

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:route_investigation_playbooks:condition_4:url:custom_function_result.data.output"])

    filtered_cf_result_0_data_output = [item[0] for item in filtered_cf_result_0]

    inputs = {
        "url": filtered_cf_result_0_data_output,
        "hash": [],
        "domain": filtered_cf_result_0_data_output,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "es8_risk_findings_response/Splunk_Attack_Analyzer_Dynamic_Analysis_ES", returns the playbook_run_id
    playbook_run_id = phantom.playbook("es8_risk_findings_response/Splunk_Attack_Analyzer_Dynamic_Analysis_ES", container=container, name="splunk_attack_analyzer_dynamic_analysis", callback=add_task_note_2, inputs=inputs)

    return


@phantom.playbook_block()
def add_task_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""## Observable JSON:\n\n{0}\n\n\n\n\n{1}\n\n""",
        parameters=[
            "playbook_splunk_attack_analyzer_dynamic_analysis_1:playbook_output:observable",
            "playbook_splunk_attack_analyzer_dynamic_analysis_1:playbook_output:report"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    playbook_splunk_attack_analyzer_dynamic_analysis_1_output_observable = phantom.collect2(container=container, datapath=["playbook_splunk_attack_analyzer_dynamic_analysis_1:playbook_output:observable"])
    playbook_splunk_attack_analyzer_dynamic_analysis_1_output_report = phantom.collect2(container=container, datapath=["playbook_splunk_attack_analyzer_dynamic_analysis_1:playbook_output:report"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for playbook_splunk_attack_analyzer_dynamic_analysis_1_output_observable_item in playbook_splunk_attack_analyzer_dynamic_analysis_1_output_observable:
            for playbook_splunk_attack_analyzer_dynamic_analysis_1_output_report_item in playbook_splunk_attack_analyzer_dynamic_analysis_1_output_report:
                for get_task_id_1_result_item in get_task_id_1_result_data:
                    for get_phase_id_1_result_item in get_phase_id_1_result_data:
                        if get_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                            parameters.append({
                                "id": get_finding_or_investigation_1_result_item[0],
                                "title": "Dynamic Analysis from Splunk Attack Analyzer:",
                                "content": content_formatted_string,
                                "task_id": get_task_id_1_result_item[0],
                                "phase_id": get_phase_id_1_result_item[0],
                                "response_plan_id": get_finding_or_investigation_1_result_item[1],
                            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_2", assets=["builtin_mc_connector"], callback=join_update_task_in_current_phase_1)

    return


@phantom.playbook_block()
def join_update_task_in_current_phase_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_update_task_in_current_phase_1() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_update_task_in_current_phase_1_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_update_task_in_current_phase_1_called", value="update_task_in_current_phase_1")

    # call connected block "update_task_in_current_phase_1"
    update_task_in_current_phase_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def update_task_in_current_phase_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_task_in_current_phase_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_task_in_current_phase_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            if get_finding_or_investigation_1_result_item[0] is not None and get_task_id_1_result_item[0] is not None:
                parameters.append({
                    "id": get_finding_or_investigation_1_result_item[0],
                    "status": "Ended",
                    "task_id": get_task_id_1_result_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update task in current phase", parameters=parameters, name="update_task_in_current_phase_1", assets=["builtin_mc_connector"], callback=run_query_2)

    return


@phantom.playbook_block()
def refresh_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("refresh_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id"])

    parameters = []

    # build parameters list for 'refresh_finding_or_investigation_1' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None:
            parameters.append({
                "id": finding_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("refresh finding or investigation", parameters=parameters, name="refresh_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=get_finding_or_investigation_1)

    return


@phantom.playbook_block()
def run_query_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""| eval threat_indicator_hash = \"{0}\"\n| eval threat_indicator_ip = \"{1}\"\n| eval threat_indicator_domain = \"{2}\"\n| eval threat_indicator_url = \"{3}\"\n| eval threat_indicator_process = \"{4}\"\n| fields threat_indicator_hash threat_indicator_ip threat_indicator_domain threat_indicator_url threat_indicator_process\n| `add_events({5})`\n""",
        parameters=[
            "file_hash:custom_function_result.data.output",
            "ip:custom_function_result.data.output",
            "domain:custom_function_result.data.output",
            "url:custom_function_result.data.output",
            "process:custom_function_result.data.output",
            "refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id"
        ])

    file_hash__result = phantom.collect2(container=container, datapath=["file_hash:custom_function_result.data.output"])
    ip__result = phantom.collect2(container=container, datapath=["ip:custom_function_result.data.output"])
    domain__result = phantom.collect2(container=container, datapath=["domain:custom_function_result.data.output"])
    url__result = phantom.collect2(container=container, datapath=["url:custom_function_result.data.output"])
    process__result = phantom.collect2(container=container, datapath=["process:custom_function_result.data.output"])
    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'run_query_2' call
    for file_hash__result_item in file_hash__result:
        for ip__result_item in ip__result:
            for domain__result_item in domain__result:
                for url__result_item in url__result:
                    for process__result_item in process__result:
                        for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
                            if query_formatted_string is not None:
                                parameters.append({
                                    "query": query_formatted_string,
                                    "command": "| makeresults",
                                    "search_mode": "verbose",
                                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_2", assets=["splunk"])

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