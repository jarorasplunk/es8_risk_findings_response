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
        template="""datamodel Risk.All_Risk \n| search [ | tstats `summariesonly` `common_fbd_fields`, values(All_Risk.threat_object) as threat_object from datamodel=Risk.All_Risk where earliest={0} latest={1} by All_Risk.normalized_risk_object, All_Risk.risk_object_type, index\n| `get_mitre_annotations`\n| rename All_Risk.normalized_risk_object as normalized_risk_object, All_Risk.risk_object_type as risk_object_type\n| `generate_findings_summary`\n| stats list(*) as * limit=1000000, sum(int_risk_score_sum) as risk_score by `fbd_grouping(normalized_risk_object)`\n| `dedup_and_compute_common_fbd_fields`, threat_object=mvdedup(threat_object), risk_object_type=mvdedup(risk_object_type), num_mitre_techniques=mvcount('annotations.mitre_attack'), annotations.mitre_attack=mvdedup('annotations.mitre_attack'), annotations.mitre_attack.mitre_tactic=mvdedup('annotations.mitre_attack.mitre_tactic'), mitre_tactic_id_count=mvcount('annotations.mitre_attack.mitre_tactic'), mitre_technique_id_count=mvcount('annotations.mitre_attack')\n| fillnull value=0 num_mitre_techniques, mitre_tactic_id_count, mitre_technique_id_count, total_event_count, risk_score\n| fields - int_risk_score_sum, int_findings_count, individual_threat_object_count, contributing_event_ids\n| `drop_dm_object_name(\"All_Risk\")`\n| where normalized_risk_object=\"{2}\" AND risk_object_type=\"{3}\"\n| where num_mitre_techniques>3 OR risk_score>100 OR total_event_count>5\n| eval all_finding_ids=mvdedup(finding_ids)\n| fields all_finding_ids\n| mvexpand all_finding_ids\n| rename all_finding_ids AS source_event_id ]\n| rename annotations.mitre_attack.mitre_tactic as mitre_tactic, annotations.mitre_attack.mitre_technique as mitre_technique, annotations.mitre_attack.mitre_technique_id as mitre_technique_id\n| fields mitre_tactic, mitre_technique, mitre_technique_id, risk_message, threat_object, threat_object_type""",
        parameters=[
            "finding:consolidated_findings.info_min_time",
            "finding:consolidated_findings.info_max_time",
            "finding:consolidated_findings.normalized_risk_object",
            "finding:consolidated_findings.risk_object_type"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.info_min_time","finding:consolidated_findings.info_max_time","finding:consolidated_findings.normalized_risk_object","finding:consolidated_findings.risk_object_type"])

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
        user_enrichment_note(action=action, success=success, container=container, results=results, handle=handle)
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
        asset_enrichment_note(action=action, success=success, container=container, results=results, handle=handle)
        return

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
            "finding:consolidated_findings.normalized_risk_object"
        ])
    content_formatted_string = phantom.format(
        container=container,
        template="""### Splunk Enterprise Security has detected that {0} '**{1}**' generated {2} points of risk.\n\n### Full statistics and timeline on this user's risk behavior can be found [here](https://{6}/app/SplunkEnterpriseSecuritySuite/risk_analysis?earliest={3}&latest={4}&form.risk_object_type_raw={0}&form.risk_object_raw={1}) \n\n\n\n# MITRE ATT&CK®\nSplunk SOAR has aggregated and aligned the following risk rules to ATT&CK Tactics and Techniques.\n\n{5}""",
        parameters=[
            "finding:consolidated_findings.risk_object_type",
            "finding:consolidated_findings.normalized_risk_object",
            "finding:consolidated_findings.risk_score",
            "finding:consolidated_findings.info_min_time",
            "finding:consolidated_findings.info_max_time",
            "mitre_format:custom_function:output",
            "asset_get_attributes_1:custom_function_result.data.configuration.device"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:consolidated_findings.normalized_risk_object","finding:consolidated_findings.risk_object_type","finding:consolidated_findings.risk_score","finding:consolidated_findings.info_min_time","finding:consolidated_findings.info_max_time","finding:response_plans.*.id"])
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_1", assets=["builtin_mc_connector"], callback=join_update_task_in_current_phase_1)

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

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_task_in_current_phase_1' call
    for finding_data_item in finding_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            if finding_data_item[0] is not None and get_task_id_1_result_item[0] is not None:
                parameters.append({
                    "id": finding_data_item[0],
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

    template = """Review the user: {0} details in Assets and Identities database:\n\nhttps://es8-shw-46d5351519c4f2.stg.splunkcloud.com/en-GB/app/SplunkEnterpriseSecuritySuite/identity_center?form.username={0}&form.priority=*&form.bunit=*&form.category=*&form.watchlist=*\n\nGather intelligence about the user {0} in Asset and Risk Intelligence:\n\nhttps://es8-shw-46d5351519c4f2.stg.splunkcloud.com/en-GB/app/SplunkAssetRiskIntelligence/ari_user_search?form.time.earliest=-30d%40d&form.time.latest=now&form.profile=ip&form.series={0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "finding:consolidated_findings.normalized_risk_object"
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

    template = """Review the asset: {0} details in Assets and Identities database:\n\nhttps://es8-shw-46d5351519c4f2.stg.splunkcloud.com/en-GB/app/SplunkEnterpriseSecuritySuite/asset_center?form.pci_domain=*&form.asset={0}&form.priority=*&form.bunit=*&form.category=*&form.owner=*\n\nGather intelligence about the user {0} in Asset and Risk Intelligence:\n\nhttps://es8-shw-46d5351519c4f2.stg.splunkcloud.com/en-GB/app/SplunkAssetRiskIntelligence/ari_network_search?form.time.earliest=-7d%40h&form.time.latest=now&form.profile=ip&form.series={0}"""

    # parameter list for template variable replacement
    parameters = [
        "finding:consolidated_findings.normalized_risk_object"
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

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    asset_enrichment_note = phantom.get_format_data(name="asset_enrichment_note")

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for finding_data_item in finding_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if finding_data_item[0] is not None and asset_enrichment_note is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and finding_data_item[1] is not None:
                    parameters.append({
                        "id": finding_data_item[0],
                        "title": "Asset enrichment:",
                        "content": asset_enrichment_note,
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_2", assets=["builtin_mc_connector"], callback=join_update_task_in_current_phase_1)

    return


@phantom.playbook_block()
def add_task_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    user_enrichment_note = phantom.get_format_data(name="user_enrichment_note")

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for finding_data_item in finding_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if finding_data_item[0] is not None and finding_data_item[1] is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and user_enrichment_note is not None:
                    parameters.append({
                        "id": finding_data_item[0],
                        "response_plan_id": finding_data_item[1],
                        "task_id": get_task_id_1_result_item[0],
                        "phase_id": get_phase_id_1_result_item[0],
                        "title": "User enrichment:",
                        "content": user_enrichment_note,
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