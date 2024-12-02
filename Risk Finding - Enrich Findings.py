"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_phase_id_1' block
    get_phase_id_1(container=container)

    return

@phantom.playbook_block()
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template=""" datamodel:Risk \n| search normalized_risk_object=\"{0}\" risk_object_type=\"{3}\" \n| where _time>={1} AND _time<={2}  | eval risk_event_id = if(isnull(risk_event_id), index + \"_\" + _cd + \"_\" + splunk_server, risk_event_id) | eventstats count by risk_event_id | where count < 2 \n| eval risk_message=coalesce(risk_message,source) \n| eval threat_zip = mvzip(threat_object, threat_object_type) \n| rename annotations.mitre_attack.mitre_technique_id as mitre_technique_id annotations.mitre_attack.mitre_tactic as mitre_tactic annotations.mitre_attack.mitre_technique as mitre_technique \n| fields - annotations* orig_sid orig_rid risk_factor* splunk_server host sourcetype tag threat_object* \n| stats list(risk_event_id) as risk_event_ids list(_time) as original_timestamps count as _event_count sum(calculated_risk_score) as _total_risk_score earliest(_time) as earliest latest(_time) as latest values(*) as * by search_name risk_message \n| where NOT (match(source, \"Splunk\\sSOAR\") AND _total_risk_score<=0) \n| fields mitre* _event_count _total_risk_score original_timestamps threat_zip risk_event_ids threat_object\n    [| rest /services/datamodel/model \n    | search eai:acl.app IN (Splunk_SA_CIM, SA-IdentityManagement, SA-NetworkProtection, SA-ThreatIntelligence, DA-ESS-ThreatIntelligence) \n    | fields description \n    | spath input=description path=objects{{}}.fields{{}}.fieldName \n    | spath input=description path=objects{{}}.calculations{{}}.outputFields{{}}.fieldName \n    | eval fieldNames=mvappend('objects{{}}.fields{{}}.fieldName', 'objects{{}}.calculations{{}}.outputFields{{}}.fieldName') \n    | stats values(fieldNames) as fieldNames \n    | mvexpand fieldNames \n    | regex fieldNames=\"^[_a-z]+$\" \n    | stats values(fieldNames) as search] \n| sort + latest \n| `uitime(earliest)` \n| `uitime(latest)` \n| eval _time=latest \n| rex field=threat_zip \"(?<threat_object>.*)\\,(?<threat_object_type>.*)\" \n| fields - threat_zip""",
        parameters=[
            "finding:consolidated_findings.risk_object",
            "finding:consolidated_findings.info_min_time",
            "finding:consolidated_findings.info_max_time",
            "finding:consolidated_findings.risk_object_type"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.risk_object","finding:consolidated_findings.info_min_time","finding:consolidated_findings.info_max_time","finding:consolidated_findings.risk_object_type"])

    parameters = []

    # build parameters list for 'run_query_1' call
    for finding_data_item in finding_data:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "| from ",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["splunk"], callback=run_query_decision)

    return


@phantom.playbook_block()
def run_query_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["run_query_1:action_result.summary.total_events", ">", 0]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        asset_get_attributes_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def mitre_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("mitre_format() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.mitre_tactic","run_query_1:action_result.data.*.mitre_technique","run_query_1:action_result.data.*.mitre_technique_id","run_query_1:action_result.data.*.risk_message"], action_results=results)

    run_query_1_result_item_0 = [item[0] for item in run_query_1_result_data]
    run_query_1_result_item_1 = [item[1] for item in run_query_1_result_data]
    run_query_1_result_item_2 = [item[2] for item in run_query_1_result_data]
    run_query_1_result_item_3 = [item[3] for item in run_query_1_result_data]

    mitre_format__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    from collections import OrderedDict 
    from operator import getitem 
    
    def mitre_sorter(item):
        tactic_list = [
            'reconnaissance', 'resource-development', 'initial-access', 'execution', 
            'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 
            'discovery', 'lateral-movement', 'collection', 'command-and-control', 
            'exfiltration', 'impact'
        ]
        index_map = {v: i for i, v in enumerate(tactic_list)}
        if ',' in item[0]:
            first_item = item[0].split(', ')[1]
            return index_map[first_item]
        else:
            return index_map[item[0]]

    
    def replace_all(text):
        char_list = ['[', ']', '"', "'"]
        for char in char_list:
            text = text.replace(char, '')
        return text

    mitre_dictionary = {}
    for mitre_tactic, mitre_technique, mitre_technique_id, risk_message in zip(run_query_1_result_item_0, run_query_1_result_item_1, run_query_1_result_item_2, run_query_1_result_item_3):
        
        mitre_tactic = replace_all(json.dumps(mitre_tactic)) if mitre_tactic else None
        mitre_technique = replace_all(json.dumps(mitre_technique)) if mitre_technique else None
        mitre_technique_id = replace_all(json.dumps(mitre_technique_id)) if mitre_technique_id else None
        
        if mitre_tactic and mitre_tactic not in mitre_dictionary.keys():
            mitre_dictionary[mitre_tactic] = {mitre_technique: {'id': mitre_technique_id, 'risk_message': [risk_message]}}
        elif mitre_tactic and mitre_tactic in mitre_dictionary.keys():
            if mitre_technique and mitre_technique not in mitre_dictionary[mitre_tactic].keys():
                mitre_dictionary[mitre_tactic][mitre_technique] = {'id': mitre_technique_id, 'risk_message': [risk_message]}
            elif mitre_technique and mitre_technique in mitre_dictionary[mitre_tactic].keys():
                if risk_message not in mitre_dictionary[mitre_tactic][mitre_technique]['risk_message']:
                    mitre_dictionary[mitre_tactic][mitre_technique]['risk_message'].append(risk_message)
    
    mitre_copy = mitre_dictionary.copy()
    for k,v in mitre_copy.items():
        sorted_techniques = OrderedDict(sorted(v.items(),
                                               key = lambda x: getitem(x[1], 'id')
                                              )
                                       ) 
        for a,b in sorted_techniques.items():
            sorted_techniques[a] = b['risk_message']
        mitre_copy[k] = sorted_techniques

    final_dictionary = sorted(mitre_copy.items(), key=mitre_sorter)
    final_format = ""
    for tactics in final_dictionary:
        if ',' in tactics[0]:
            tactic_list = tactics[0].split(', ')
            final_format += "\n ## "
            for tactic in tactic_list[:-1]:
                split_tactic = tactic.split('-')
                for item in split_tactic[:-1]:
                    final_format += "{} ".format(item.capitalize())
                final_format += "{}, ".format(split_tactic[-1].capitalize())
            split_tactic = tactic_list[-1].split('-')
            for item in split_tactic[:-1]:
                final_format += "{} ".format(item.capitalize())
            final_format += "{}".format(split_tactic[-1].capitalize())
        else:
            tactic_list = tactics[0].split('-')
            final_format += "\n ## "
            for tactic in tactic_list[:-1]:
                final_format += "{} ".format(tactic.capitalize())
            final_format += "{}".format(tactic_list[-1].capitalize())
        for k,v in tactics[1].items():
            final_format += "\n - #### {}: {}".format(k, mitre_dictionary[tactics[0]][k]['id'])
            for risk_message in v:
                final_format += "\n   - ```{}```".format(risk_message)
        final_format += "\n"
    

    if final_format:
    	mitre_format__output = final_format
    else:
        mitre_format__output = "No Tactics / Techniques available in contributing risk events."
	

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="mitre_format:output", value=json.dumps(mitre_format__output))

    add_task_note_1(container=container)

    return


@phantom.playbook_block()
def add_finding_or_investigation_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_finding_or_investigation_note_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""SOAR Analysis for: {0}\n""",
        parameters=[
            "finding:consolidated_findings.risk_object"
        ])
    content_formatted_string = phantom.format(
        container=container,
        template="""### Splunk Enterprise Security has detected that {0} '**{1}**' generated {2} points of risk.\n\n### Full statistics and timeline on this user's risk behavior can be found [here](/app/SplunkEnterpriseSecuritySuite/risk_analysis?earliest={3}&latest={4}&form.risk_object_type_raw={0}&form.risk_object_raw={1})\n\n# MITRE ATT&CK®\nSplunk SOAR has aggregated and aligned the following risk rules to ATT&CK Tactics and Techniques.\n\n{5}""",
        parameters=[
            "finding:consolidated_findings.risk_object_type",
            "finding:consolidated_findings.risk_object",
            "finding:consolidated_findings.risk_score",
            "finding:consolidated_findings.info_min_time",
            "finding:consolidated_findings.info_max_time",
            "mitre_format:custom_function:output"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:id","finding:consolidated_findings.risk_object","finding:consolidated_findings.risk_object_type","finding:consolidated_findings.risk_score","finding:consolidated_findings.info_min_time","finding:consolidated_findings.info_max_time"])
    mitre_format__output = json.loads(_ if (_ := phantom.get_run_data(key="mitre_format:output")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'add_finding_or_investigation_note_1' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None and title_formatted_string is not None and content_formatted_string is not None:
            parameters.append({
                "id": finding_data_item[0],
                "title": title_formatted_string,
                "content": content_formatted_string,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add finding or investigation note", parameters=parameters, name="add_finding_or_investigation_note_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def playbook_azure_ad_graph_user_attribute_lookup_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_azure_ad_graph_user_attribute_lookup_2() called")

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.normalized_risk_object"])

    finding_consolidated_findings_normalized_risk_object = [item[0] for item in finding_data]

    inputs = {
        "user": finding_consolidated_findings_normalized_risk_object,
        "device": finding_consolidated_findings_normalized_risk_object,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Azure_AD_Graph_User_Attribute_Lookup", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Azure_AD_Graph_User_Attribute_Lookup", container=container, name="playbook_azure_ad_graph_user_attribute_lookup_2", callback=playbook_azure_ad_graph_user_attribute_lookup_2_callback, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_azure_ad_graph_user_attribute_lookup_2_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_azure_ad_graph_user_attribute_lookup_2_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


@phantom.playbook_block()
def playbook_crowdstrike_oauth_api_device_attribute_lookup_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_crowdstrike_oauth_api_device_attribute_lookup_1() called")

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.normalized_risk_object"])

    finding_consolidated_findings_normalized_risk_object = [item[0] for item in finding_data]

    inputs = {
        "device": finding_consolidated_findings_normalized_risk_object,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CrowdStrike_OAuth_API_Device_Attribute_Lookup", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CrowdStrike_OAuth_API_Device_Attribute_Lookup", container=container, name="playbook_crowdstrike_oauth_api_device_attribute_lookup_1", callback=playbook_crowdstrike_oauth_api_device_attribute_lookup_1_callback, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_crowdstrike_oauth_api_device_attribute_lookup_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_crowdstrike_oauth_api_device_attribute_lookup_1_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["finding:consolidated_findings.risk_object_type", "==", "user"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook_azure_ad_graph_user_attribute_lookup_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["finding:consolidated_findings.risk_object_type", "==", "system"]
        ],
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        playbook_azure_ad_graph_user_attribute_lookup_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def playbook_azure_ad_graph_user_attribute_lookup_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_azure_ad_graph_user_attribute_lookup_1() called")

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.normalized_risk_object"])

    finding_consolidated_findings_normalized_risk_object = [item[0] for item in finding_data]

    inputs = {
        "user": [],
        "device": finding_consolidated_findings_normalized_risk_object,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Azure_AD_Graph_User_Attribute_Lookup", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Azure_AD_Graph_User_Attribute_Lookup", container=container, name="playbook_azure_ad_graph_user_attribute_lookup_1", callback=playbook_crowdstrike_oauth_api_device_attribute_lookup_1, inputs=inputs)

    return


@phantom.playbook_block()
def add_finding_or_investigation_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_finding_or_investigation_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:id"])
    format_2 = phantom.get_format_data(name="format_2")

    parameters = []

    # build parameters list for 'add_finding_or_investigation_note_2' call
    for finding_data_item in finding_data:
        if finding_data_item[0] is not None and format_2 is not None:
            parameters.append({
                "id": finding_data_item[0],
                "title": "Risk Object Enrichment",
                "content": format_2,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add finding or investigation note", parameters=parameters, name="add_finding_or_investigation_note_2", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_2() called")

    template = """Entity Enrichment Information:\n{0}\n{1}\n{2}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_azure_ad_graph_user_attribute_lookup_2:playbook_output:observable",
        "playbook_crowdstrike_oauth_api_device_attribute_lookup_1:playbook_output:observable",
        "playbook_azure_ad_graph_user_attribute_lookup_1:playbook_output:observable"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_2", drop_none=True)

    add_finding_or_investigation_note_2(container=container)

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
                "phase_name": "Preprocess",
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
                "task_name": "Enrich findings",
                "phase_name": "Preprocess",
                "response_template_name": finding_data_item[1],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get task id", parameters=parameters, name="get_task_id_1", assets=["builtin_mc_connector"], callback=get_task_id_1_callback)

    return


@phantom.playbook_block()
def get_task_id_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_task_id_1_callback() called")

    
    run_query_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    decision_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def add_task_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""SOAR Analysis for: {0}\n""",
        parameters=[
            "finding:consolidated_findings.risk_object"
        ])
    content_formatted_string = phantom.format(
        container=container,
        template="""### Splunk Enterprise Security has detected that {0} '**{1}**' generated {2} points of risk.\n\n### Full statistics and timeline on this user's risk behavior can be found [here](https://{6}/app/SplunkEnterpriseSecuritySuite/risk_analysis?earliest={3}&latest={4}&form.risk_object_type_raw={0}&form.risk_object_raw={1})\n\n# MITRE ATT&CK®\nSplunk SOAR has aggregated and aligned the following risk rules to ATT&CK Tactics and Techniques.\n\n{5}""",
        parameters=[
            "finding:consolidated_findings.risk_object_type",
            "finding:consolidated_findings.risk_object",
            "finding:consolidated_findings.risk_score",
            "finding:consolidated_findings.info_min_time",
            "finding:consolidated_findings.info_max_time",
            "mitre_format:custom_function:output",
            "asset_get_attributes_1:custom_function_result.data.configuration.device"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:consolidated_findings.risk_object","finding:consolidated_findings.risk_object_type","finding:consolidated_findings.risk_score","finding:consolidated_findings.info_min_time","finding:consolidated_findings.info_max_time","finding:response_plans.*.id"])
    asset_get_attributes_1__result = phantom.collect2(container=container, datapath=["asset_get_attributes_1:custom_function_result.data.configuration.device"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    mitre_format__output = json.loads(_ if (_ := phantom.get_run_data(key="mitre_format:output")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for finding_data_item in finding_data:
        for asset_get_attributes_1__result_item in asset_get_attributes_1__result:
            for get_task_id_1_result_item in get_task_id_1_result_data:
                for get_phase_id_1_result_item in get_phase_id_1_result_data:
                    if finding_data_item[0] is not None and title_formatted_string is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and finding_data_item[6] is not None:
                        parameters.append({
                            "id": finding_data_item[0],
                            "title": title_formatted_string,
                            "content": content_formatted_string,
                            "task_id": get_task_id_1_result_item[0],
                            "phase_id": get_phase_id_1_result_item[0],
                            "response_plan_id": finding_data_item[6],
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
def asset_get_attributes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("asset_get_attributes_1() called")

    parameters = []

    parameters.append({
        "asset": "splunk",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/asset_get_attributes", parameters=parameters, name="asset_get_attributes_1", callback=mitre_format)

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