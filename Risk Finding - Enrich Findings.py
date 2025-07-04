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
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""datamodel Risk.All_Risk \n| search [ | tstats `summariesonly` `common_fbd_fields`, values(All_Risk.threat_object) as threat_object from datamodel=Risk.All_Risk where earliest={0} latest={1} by All_Risk.normalized_risk_object, All_Risk.risk_object_type, index\n| `get_mitre_annotations`\n| rename All_Risk.normalized_risk_object as normalized_risk_object, All_Risk.risk_object_type as risk_object_type\n| `generate_findings_summary`\n| stats list(*) as * limit=1000000, sum(int_risk_score_sum) as risk_score by `fbd_grouping(normalized_risk_object)`\n| `dedup_and_compute_common_fbd_fields`, threat_object=mvdedup(threat_object), risk_object_type=mvdedup(risk_object_type), num_mitre_techniques=mvcount('annotations.mitre_attack'), annotations.mitre_attack=mvdedup('annotations.mitre_attack'), annotations.mitre_attack.mitre_tactic=mvdedup('annotations.mitre_attack.mitre_tactic'), mitre_tactic_id_count=mvcount('annotations.mitre_attack.mitre_tactic'), mitre_technique_id_count=mvcount('annotations.mitre_attack')\n| fillnull value=0 num_mitre_techniques, mitre_tactic_id_count, mitre_technique_id_count, total_event_count, risk_score\n| fields - int_risk_score_sum, int_findings_count, individual_threat_object_count, contributing_event_ids\n| `drop_dm_object_name(\"All_Risk\")`\n| where normalized_risk_object=\"{2}\" AND risk_object_type=\"{3}\"\n| where num_mitre_techniques>3 OR risk_score>100 OR total_event_count>5\n| eval all_finding_ids=mvdedup(finding_ids)\n| fields all_finding_ids\n| mvexpand all_finding_ids\n| rename all_finding_ids AS source_event_id ]\n| rename annotations.mitre_attack.mitre_tactic as mitre_tactic, annotations.mitre_attack.mitre_technique as mitre_technique, annotations.mitre_attack.mitre_technique_id as mitre_technique_id\n| fields mitre_tactic, mitre_technique, mitre_technique_id, risk_message, threat_object, threat_object_type, threat_match_value, threat_match_field""",
        parameters=[
            "run_query_parameters:custom_function:info_min_time",
            "run_query_parameters:custom_function:info_max_time",
            "run_query_parameters:custom_function:normalized_risk_object",
            "run_query_parameters:custom_function:risk_object_type"
        ])

    run_query_parameters__info_min_time = json.loads(_ if (_ := phantom.get_run_data(key="run_query_parameters:info_min_time")) != "" else "null")  # pylint: disable=used-before-assignment
    run_query_parameters__info_max_time = json.loads(_ if (_ := phantom.get_run_data(key="run_query_parameters:info_max_time")) != "" else "null")  # pylint: disable=used-before-assignment
    run_query_parameters__normalized_risk_object = json.loads(_ if (_ := phantom.get_run_data(key="run_query_parameters:normalized_risk_object")) != "" else "null")  # pylint: disable=used-before-assignment
    run_query_parameters__risk_object_type = json.loads(_ if (_ := phantom.get_run_data(key="run_query_parameters:risk_object_type")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if query_formatted_string is not None:
        parameters.append({
            "query": query_formatted_string,
            "command": "| from ",
            "search_mode": "smart",
            "add_raw_field": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["es"], callback=run_query_decision)

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
        conditions_dps=[
            ["run_query_1:action_result.summary.total_events", ">", 0]
        ],
        name="run_query_decision:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        mitre_format_findings(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def mitre_format_findings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("mitre_format_findings() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.mitre_tactic","run_query_1:action_result.data.*.mitre_technique","run_query_1:action_result.data.*.mitre_technique_id","run_query_1:action_result.data.*.risk_message"], action_results=results)

    run_query_1_result_item_0 = [item[0] for item in run_query_1_result_data]
    run_query_1_result_item_1 = [item[1] for item in run_query_1_result_data]
    run_query_1_result_item_2 = [item[2] for item in run_query_1_result_data]
    run_query_1_result_item_3 = [item[3] for item in run_query_1_result_data]

    mitre_format_findings__output = None

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
    	mitre_format_findings__output = final_format
    else:
        mitre_format_findings__output = "No Tactics / Techniques available in contributing risk events."
	

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="mitre_format_findings__inputs:0:run_query_1:action_result.data.*.mitre_tactic", value=json.dumps(run_query_1_result_item_0))
    phantom.save_block_result(key="mitre_format_findings__inputs:1:run_query_1:action_result.data.*.mitre_technique", value=json.dumps(run_query_1_result_item_1))
    phantom.save_block_result(key="mitre_format_findings__inputs:2:run_query_1:action_result.data.*.mitre_technique_id", value=json.dumps(run_query_1_result_item_2))
    phantom.save_block_result(key="mitre_format_findings__inputs:3:run_query_1:action_result.data.*.risk_message", value=json.dumps(run_query_1_result_item_3))

    phantom.save_block_result(key="mitre_format_findings:output", value=json.dumps(mitre_format_findings__output))

    add_task_note_1(container=container)

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type", "==", "user"]
        ],
        conditions_dps=[
            ["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type", "==", "user"]
        ],
        name="decision_3:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        user_enrichment_note(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type", "==", "system"]
        ],
        conditions_dps=[
            ["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type", "==", "system"]
        ],
        name="decision_3:condition_2",
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        asset_enrichment_note(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def get_phase_id_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_phase_id_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.name","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_phase_id_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "phase_name": "Preprocess",
                "response_template_name": get_finding_or_investigation_1_result_item[1],
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

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.name","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_task_id_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        if get_finding_or_investigation_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
            parameters.append({
                "id": get_finding_or_investigation_1_result_item[0],
                "task_name": "Enrich findings",
                "phase_name": "Preprocess",
                "response_template_name": get_finding_or_investigation_1_result_item[1],
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

    
    decision_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    asset_get_attributes_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def add_task_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""SOAR Analysis for: {0}\n""",
        parameters=[
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object"
        ])
    content_formatted_string = phantom.format(
        container=container,
        template="""### Splunk Enterprise Security has detected that {0} '**{1}**' generated {2} points of risk.\n\n### Full statistics and timeline on this user's risk behavior can be found [here](https://{6}/app/SplunkEnterpriseSecuritySuite/risk_analysis?earliest={3}&latest={4}&form.risk_object_type_raw={0}&form.risk_object_raw={1}) \n\n\n\n# MITRE ATT&CK®\nSplunk SOAR has aggregated and aligned the following risk rules to ATT&CK Tactics and Techniques.\n\n{5}""",
        parameters=[
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_score",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_min_time",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_max_time",
            "mitre_format_findings:custom_function:output",
            "asset_get_attributes_1:custom_function_result.data.configuration.device"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_score","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_min_time","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_max_time","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    asset_get_attributes_1__result = phantom.collect2(container=container, datapath=["asset_get_attributes_1:custom_function_result.data.configuration.device"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    mitre_format_findings__output = json.loads(_ if (_ := phantom.get_run_data(key="mitre_format_findings:output")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for asset_get_attributes_1__result_item in asset_get_attributes_1__result:
            for get_task_id_1_result_item in get_task_id_1_result_data:
                for get_phase_id_1_result_item in get_phase_id_1_result_data:
                    if get_finding_or_investigation_1_result_item[0] is not None and title_formatted_string is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[6] is not None:
                        parameters.append({
                            "id": get_finding_or_investigation_1_result_item[0],
                            "title": title_formatted_string,
                            "content": content_formatted_string,
                            "task_id": get_task_id_1_result_item[0],
                            "phase_id": get_phase_id_1_result_item[0],
                            "response_plan_id": get_finding_or_investigation_1_result_item[6],
                        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_1", assets=["builtin_mc_connector"], callback=finding_threat_objects)

    return


@phantom.playbook_block()
def asset_get_attributes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("asset_get_attributes_1() called")

    parameters = []

    parameters.append({
        "asset": "es",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/asset_get_attributes", parameters=parameters, name="asset_get_attributes_1", callback=decision_4)

    return


@phantom.playbook_block()
def join_update_task_in_current_phase_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_update_task_in_current_phase_1() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_update_task_in_current_phase_1_called"):
        return

    if phantom.completed(code_names=["finding_threat_objects", "int_findings_threat_objects"], action_names=["add_task_note_6"]):
        # save the state that the joined function has now been called
        phantom.save_block_result(key="join_update_task_in_current_phase_1_called", value="update_task_in_current_phase_1")

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
                    "name": "Enrich findings",
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

    phantom.act("update task in current phase", parameters=parameters, name="update_task_in_current_phase_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def user_enrichment_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("user_enrichment_note() called")

    template = """Review the user: {0} details:\n[Assets and Identities database](/en-GB/app/SplunkEnterpriseSecuritySuite/identity_center?form.username={0}&form.priority=*&form.bunit=*&form.category=*&form.watchlist=*)\n\n\n\nGather intelligence about the user: {0} in ARI:\n\n[Asset and Risk Intelligence](/en-GB/app/SplunkAssetRiskIntelligence/ari_user_search?form.time.earliest=-30d%40d&form.time.latest=now&form.profile=ip&form.series={0})`\n"""

    # parameter list for template variable replacement
    parameters = [
        "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="user_enrichment_note")

    add_task_note_3(container=container)

    return


@phantom.playbook_block()
def asset_enrichment_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("asset_enrichment_note() called")

    template = """Review the asset: {0} details:\n[Assets and Identities database](https://i-0e6bc36a44836889b.splunk.show/en-GB/app/SplunkEnterpriseSecuritySuite/asset_center?form.pci_domain=*&form.asset={0}&form.priority=*&form.bunit=*&form.category=*&form.owner=*)\n\n\nGather intelligence about the asset: {0} in ARI:\n[Asset and Risk Intelligence](https://i-0e6bc36a44836889b.splunk.show/en-GB/app/SplunkAssetRiskIntelligence/ari_network_search?form.time.earliest=-7d%40h&form.time.latest=now&form.profile=ip&form.series={0})"""

    # parameter list for template variable replacement
    parameters = [
        "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="asset_enrichment_note")

    add_task_note_2(container=container)

    return


@phantom.playbook_block()
def add_task_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    asset_enrichment_note = phantom.get_format_data(name="asset_enrichment_note")

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and asset_enrichment_note is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": "Asset information:",
                        "content": asset_enrichment_note,
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
def add_task_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    user_enrichment_note = phantom.get_format_data(name="user_enrichment_note")

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and user_enrichment_note is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": "User information:",
                        "content": user_enrichment_note,
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
def threat_objects_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threat_objects_note() called")

    template = """Below threat objects have been identified as part of this investigation:\n\n| Threat Indicator Type | Indicator Value |\n| --- | --- |\n%%\n| {0} | {1} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "finding_threat_objects:custom_function:threat_object_type",
        "finding_threat_objects:custom_function:threat_object"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="threat_objects_note")

    add_task_note_4(container=container)

    return


@phantom.playbook_block()
def add_task_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_4() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    threat_objects_note = phantom.get_format_data(name="threat_objects_note")

    parameters = []

    # build parameters list for 'add_task_note_4' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and threat_objects_note is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": "Threat information:",
                        "content": threat_objects_note,
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_4", assets=["builtin_mc_connector"], callback=join_update_task_in_current_phase_1)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["finding_threat_objects:custom_function:threat_object", "is not empty"]
        ],
        conditions_dps=[
            ["finding_threat_objects:custom_function:threat_object", "is not empty"]
        ],
        name="decision_2:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        threat_objects_note(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_update_task_in_current_phase_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_4() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.count_findings", "!=", 0]
        ],
        conditions_dps=[
            ["get_finding_or_investigation_1:action_result.data.*.consolidated_findings.count_findings", "!=", 0]
        ],
        name="decision_4:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        run_query_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    run_query_2(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def run_query_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""datamodel Risk.All_Risk  \n| search _time>={0} AND _time<={1}\n| search normalized_risk_object=\"{2}\" AND risk_object_type=\"{3}\"\n    \n| rename annotations.mitre_attack.mitre_tactic as mitre_tactic, annotations.mitre_attack.mitre_technique as mitre_technique, annotations.mitre_attack.mitre_technique_id as mitre_technique_id \n| fields mitre_tactic, mitre_technique, mitre_technique_id, risk_message, threat_object, threat_object_type, threat_match_value, threat_match_field""",
        parameters=[
            "run_query_parameters:custom_function:info_min_time",
            "run_query_parameters:custom_function:info_max_time",
            "run_query_parameters:custom_function:normalized_risk_object",
            "run_query_parameters:custom_function:risk_object_type"
        ])

    run_query_parameters__info_min_time = json.loads(_ if (_ := phantom.get_run_data(key="run_query_parameters:info_min_time")) != "" else "null")  # pylint: disable=used-before-assignment
    run_query_parameters__info_max_time = json.loads(_ if (_ := phantom.get_run_data(key="run_query_parameters:info_max_time")) != "" else "null")  # pylint: disable=used-before-assignment
    run_query_parameters__normalized_risk_object = json.loads(_ if (_ := phantom.get_run_data(key="run_query_parameters:normalized_risk_object")) != "" else "null")  # pylint: disable=used-before-assignment
    run_query_parameters__risk_object_type = json.loads(_ if (_ := phantom.get_run_data(key="run_query_parameters:risk_object_type")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if query_formatted_string is not None:
        parameters.append({
            "query": query_formatted_string,
            "command": "| from ",
            "search_mode": "smart",
            "add_raw_field": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_2", assets=["es"], callback=mitre_format_int_findings)

    return


@phantom.playbook_block()
def mitre_format_int_findings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("mitre_format_int_findings() called")

    run_query_2_result_data = phantom.collect2(container=container, datapath=["run_query_2:action_result.data.*.mitre_tactic","run_query_2:action_result.data.*.mitre_technique","run_query_2:action_result.data.*.mitre_technique_id","run_query_2:action_result.data.*.risk_message"], action_results=results)

    run_query_2_result_item_0 = [item[0] for item in run_query_2_result_data]
    run_query_2_result_item_1 = [item[1] for item in run_query_2_result_data]
    run_query_2_result_item_2 = [item[2] for item in run_query_2_result_data]
    run_query_2_result_item_3 = [item[3] for item in run_query_2_result_data]

    mitre_format_int_findings__output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
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
    for mitre_tactic, mitre_technique, mitre_technique_id, risk_message in zip(run_query_2_result_item_0, run_query_2_result_item_1, run_query_2_result_item_2, run_query_2_result_item_3):
        
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
    	mitre_format_int_findings__output = final_format
    else:
        mitre_format_int_findings__output = "No Tactics / Techniques available in contributing risk events."


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="mitre_format_int_findings__inputs:0:run_query_2:action_result.data.*.mitre_tactic", value=json.dumps(run_query_2_result_item_0))
    phantom.save_block_result(key="mitre_format_int_findings__inputs:1:run_query_2:action_result.data.*.mitre_technique", value=json.dumps(run_query_2_result_item_1))
    phantom.save_block_result(key="mitre_format_int_findings__inputs:2:run_query_2:action_result.data.*.mitre_technique_id", value=json.dumps(run_query_2_result_item_2))
    phantom.save_block_result(key="mitre_format_int_findings__inputs:3:run_query_2:action_result.data.*.risk_message", value=json.dumps(run_query_2_result_item_3))

    phantom.save_block_result(key="mitre_format_int_findings:output", value=json.dumps(mitre_format_int_findings__output))

    add_task_note_5(container=container)

    return


@phantom.playbook_block()
def add_task_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_5() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""SOAR Analysis for: {0}\n""",
        parameters=[
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object"
        ])
    content_formatted_string = phantom.format(
        container=container,
        template="""### Splunk Enterprise Security has detected that {0} '**{1}**' generated {2} points of risk.\n\n### Full statistics and timeline on this user's risk behavior can be found [here](https://{6}/app/SplunkEnterpriseSecuritySuite/risk_analysis?earliest={3}&latest={4}&form.risk_object_type_raw={0}&form.risk_object_raw={1}) \n\n\n\n# MITRE ATT&CK®\nSplunk SOAR has aggregated and aligned the following risk rules to ATT&CK Tactics and Techniques.\n\n{5}""",
        parameters=[
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_score",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_min_time",
            "get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_max_time",
            "mitre_format_int_findings:custom_function:output",
            "asset_get_attributes_1:custom_function_result.data.configuration.device"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_score","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_min_time","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.info_max_time","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    asset_get_attributes_1__result = phantom.collect2(container=container, datapath=["asset_get_attributes_1:custom_function_result.data.configuration.device"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    mitre_format_int_findings__output = json.loads(_ if (_ := phantom.get_run_data(key="mitre_format_int_findings:output")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'add_task_note_5' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for asset_get_attributes_1__result_item in asset_get_attributes_1__result:
            for get_task_id_1_result_item in get_task_id_1_result_data:
                for get_phase_id_1_result_item in get_phase_id_1_result_data:
                    if get_finding_or_investigation_1_result_item[0] is not None and title_formatted_string is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[6] is not None:
                        parameters.append({
                            "id": get_finding_or_investigation_1_result_item[0],
                            "title": title_formatted_string,
                            "content": content_formatted_string,
                            "task_id": get_task_id_1_result_item[0],
                            "phase_id": get_phase_id_1_result_item[0],
                            "response_plan_id": get_finding_or_investigation_1_result_item[6],
                        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_5", assets=["builtin_mc_connector"], callback=int_findings_threat_objects)

    return


@phantom.playbook_block()
def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_5() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["int_findings_threat_objects:custom_function:threat_object", "is not empty"]
        ],
        conditions_dps=[
            ["int_findings_threat_objects:custom_function:threat_object", "is not empty"]
        ],
        name="decision_5:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        threat_objects_note_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_update_task_in_current_phase_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def threat_objects_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threat_objects_note_1() called")

    template = """Below threat objects have been identified as part of this investigation:\n\n\n| Threat Indicator Type | Indicator Value |\n| --- | --- |\n%%\n| {0} | {1} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "int_findings_threat_objects:custom_function:threat_object_type",
        "int_findings_threat_objects:custom_function:threat_object"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="threat_objects_note_1")

    add_task_note_6(container=container)

    return


@phantom.playbook_block()
def add_task_note_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_6() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    threat_objects_note_1 = phantom.get_format_data(name="threat_objects_note_1")

    parameters = []

    # build parameters list for 'add_task_note_6' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and threat_objects_note_1 is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": "Threat information:",
                        "content": threat_objects_note_1,
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_6", assets=["builtin_mc_connector"], callback=join_update_task_in_current_phase_1)

    return


@phantom.playbook_block()
def int_findings_threat_objects(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("int_findings_threat_objects() called")

    run_query_2_result_data = phantom.collect2(container=container, datapath=["run_query_2:action_result.data.*.threat_object","run_query_2:action_result.data.*.threat_object_type"], action_results=results)

    run_query_2_result_item_0 = [item[0] for item in run_query_2_result_data]
    run_query_2_result_item_1 = [item[1] for item in run_query_2_result_data]

    int_findings_threat_objects__threat_object = None
    int_findings_threat_objects__threat_object_type = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    phantom.debug(len(run_query_2_result_item_0))
    phantom.debug(len(run_query_2_result_item_1))
    def is_domain_format(value):
        # Check if it contains '.' but is not in IP address format
        parts = value.split('.')
        return len(parts) > 1 and not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    
    # Result lists
    int_findings_threat_objects__threat_object = []
    int_findings_threat_objects__threat_object_type = []

    # Iterate through both lists and remove None values and duplicates
    seen = set()
    for item1, item2 in zip(run_query_2_result_item_0, run_query_2_result_item_1):
        if item1 is not None and item2 is not None:
            is_url = item1.startswith("http://") or item1.startswith("https://")
            is_domain = not is_url and is_domain_format(item1)
            if item2 == "other":
                if is_url:
                    item2 = "url"
                elif is_domain:
                    item2 = "domain"
            pair = (item1, item2)
            if pair not in seen:
                int_findings_threat_objects__threat_object.append(item1)
                int_findings_threat_objects__threat_object_type.append(item2)
                seen.add(pair)
    
    phantom.debug(int_findings_threat_objects__threat_object)
    phantom.debug(int_findings_threat_objects__threat_object_type)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="int_findings_threat_objects__inputs:0:run_query_2:action_result.data.*.threat_object", value=json.dumps(run_query_2_result_item_0))
    phantom.save_block_result(key="int_findings_threat_objects__inputs:1:run_query_2:action_result.data.*.threat_object_type", value=json.dumps(run_query_2_result_item_1))

    phantom.save_block_result(key="int_findings_threat_objects:threat_object", value=json.dumps(int_findings_threat_objects__threat_object))
    phantom.save_block_result(key="int_findings_threat_objects:threat_object_type", value=json.dumps(int_findings_threat_objects__threat_object_type))

    decision_5(container=container)

    return


@phantom.playbook_block()
def finding_threat_objects(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("finding_threat_objects() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.threat_object","run_query_1:action_result.data.*.threat_object_type"], action_results=results)

    run_query_1_result_item_0 = [item[0] for item in run_query_1_result_data]
    run_query_1_result_item_1 = [item[1] for item in run_query_1_result_data]

    finding_threat_objects__threat_object = None
    finding_threat_objects__threat_object_type = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    phantom.debug(run_query_1_result_item_0)
    phantom.debug(run_query_1_result_item_1)
    
    
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
    for item1, item2 in zip(run_query_1_result_item_0, run_query_1_result_item_1):
        phantom.debug(item1)
        phantom.debug(item2)
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
    
    phantom.debug(finding_threat_objects__threat_object)
    phantom.debug(finding_threat_objects__threat_object_type)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="finding_threat_objects__inputs:0:run_query_1:action_result.data.*.threat_object", value=json.dumps(run_query_1_result_item_0))
    phantom.save_block_result(key="finding_threat_objects__inputs:1:run_query_1:action_result.data.*.threat_object_type", value=json.dumps(run_query_1_result_item_1))

    phantom.save_block_result(key="finding_threat_objects:threat_object", value=json.dumps(finding_threat_objects__threat_object))
    phantom.save_block_result(key="finding_threat_objects:threat_object_type", value=json.dumps(finding_threat_objects__threat_object_type))

    decision_2(container=container)

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
                "map_consolidated_findings": 1,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=run_query_parameters)

    return


@phantom.playbook_block()
def run_query_parameters(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_parameters() called")

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.consolidated_findings_map.info_min_time","get_finding_or_investigation_1:action_result.data.*.consolidated_findings_map.info_max_time","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object","get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type"], action_results=results)

    get_finding_or_investigation_1_result_item_0 = [item[0] for item in get_finding_or_investigation_1_result_data]
    get_finding_or_investigation_1_result_item_1 = [item[1] for item in get_finding_or_investigation_1_result_data]
    get_finding_or_investigation_1_result_item_2 = [item[2] for item in get_finding_or_investigation_1_result_data]
    get_finding_or_investigation_1_result_item_3 = [item[3] for item in get_finding_or_investigation_1_result_data]

    run_query_parameters__info_min_time = None
    run_query_parameters__info_max_time = None
    run_query_parameters__normalized_risk_object = None
    run_query_parameters__risk_object_type = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    run_query_parameters__info_min_time = list(get_finding_or_investigation_1_result_item_0[0].keys())[0]
    run_query_parameters__info_max_time = list(get_finding_or_investigation_1_result_item_1[0].keys())[0]
    run_query_parameters__normalized_risk_object = get_finding_or_investigation_1_result_item_2[0]
    run_query_parameters__risk_object_type = get_finding_or_investigation_1_result_item_3[0]
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="run_query_parameters__inputs:0:get_finding_or_investigation_1:action_result.data.*.consolidated_findings_map.info_min_time", value=json.dumps(get_finding_or_investigation_1_result_item_0))
    phantom.save_block_result(key="run_query_parameters__inputs:1:get_finding_or_investigation_1:action_result.data.*.consolidated_findings_map.info_max_time", value=json.dumps(get_finding_or_investigation_1_result_item_1))
    phantom.save_block_result(key="run_query_parameters__inputs:2:get_finding_or_investigation_1:action_result.data.*.consolidated_findings.normalized_risk_object", value=json.dumps(get_finding_or_investigation_1_result_item_2))
    phantom.save_block_result(key="run_query_parameters__inputs:3:get_finding_or_investigation_1:action_result.data.*.consolidated_findings.risk_object_type", value=json.dumps(get_finding_or_investigation_1_result_item_3))

    phantom.save_block_result(key="run_query_parameters:info_min_time", value=json.dumps(run_query_parameters__info_min_time))
    phantom.save_block_result(key="run_query_parameters:info_max_time", value=json.dumps(run_query_parameters__info_max_time))
    phantom.save_block_result(key="run_query_parameters:normalized_risk_object", value=json.dumps(run_query_parameters__normalized_risk_object))
    phantom.save_block_result(key="run_query_parameters:risk_object_type", value=json.dumps(run_query_parameters__risk_object_type))

    get_phase_id_1(container=container)

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