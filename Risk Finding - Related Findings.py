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
        template="""| `risk_event_timeline_search(\"{0}\",\"{1}\")` \n| eval earliest={2} \n| eval latest={3} \n| search eventtype=\"notable\" \n| stats count(source_event_id) as source_event_id_count, values(source_event_id) as source_event_id, values(annotations.mitre_attack) as annotations.mitre_attack, values(entity) as entity, values(risk_object) as risk_object, values(risk_object_type) as risk_object_type, values(normalized_risk_object) as normalized_risk_object, values(threat_object) as threat_object, values(risk_message) as risk_message, values(threat_object_type) as threat_object_type, values(_time) as _time, values(mitre_tactic) as mitre_tactic, values(mitre_tactic_id) as mitre_tactic_id, values(mitre_technique) as mitre_technique, values(mitre_technique_id) as mitre_technique_id by source\n| `add_events({4})`""",
        parameters=[
            "finding:consolidated_findings.normalized_risk_object",
            "finding:consolidated_findings.risk_object_type",
            "finding:consolidated_findings.info_min_time",
            "finding:consolidated_findings.info_max_time",
            "finding:investigation_id"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.normalized_risk_object","finding:consolidated_findings.risk_object_type","finding:consolidated_findings.info_min_time","finding:consolidated_findings.info_max_time","finding:investigation_id"])

    parameters = []

    # build parameters list for 'run_query_1' call
    for finding_data_item in finding_data:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "",
                "display": "source, source_event_id_count, source_event_id",
                "end_time": "now",
                "start_time": "-365d",
                "search_mode": "verbose",
                "attach_result": False,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["splunk"], callback=findings_exist)

    return


@phantom.playbook_block()
def related_findings_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("related_findings_note() called")

    template = """| Detection | Count |\n| --- | --- |\n%%\n| {0} | {1} |\n%%\n\n\n\n\n\n*Follow the prompt to manage these related findings in the Analyst Queue.*"""

    # parameter list for template variable replacement
    parameters = [
        "run_query_1:action_result.data.*.source",
        "run_query_1:action_result.data.*.source_event_id_count"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="related_findings_note")

    add_task_note_1(container=container)

    return


@phantom.playbook_block()
def add_task_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    related_findings_note = phantom.get_format_data(name="related_findings_note")

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for finding_data_item in finding_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if finding_data_item[0] is not None and related_findings_note is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and finding_data_item[1] is not None:
                    parameters.append({
                        "id": finding_data_item[0],
                        "title": "Related Findings in the Analyst Queue:",
                        "content": related_findings_note,
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_1", assets=["builtin_mc_connector"], callback=close_findings_prompt)

    return


@phantom.playbook_block()
def close_findings_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("close_findings_prompt() called")

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """This Risk Finding under investigation is composed of many related findings and intermediate findings.\n\nYou can browse all these related findings on a risk timeline in the Overview Tab.\n\nPlease select a response below to manage these findings in the Analyst Queue while you continue to work on the investigation.\n\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "related_findings_note:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Do you want to close these individual findings?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="close_findings_prompt", parameters=parameters, response_types=response_types, callback=decision_1)

    return


@phantom.playbook_block()
def update_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:get_finding_or_investigation_1:action_result.data.*.finding_id"])

    parameters = []

    # build parameters list for 'update_finding_or_investigation_1' call
    for filtered_result_0_item_filter_1 in filtered_result_0_data_filter_1:
        if filtered_result_0_item_filter_1[0] is not None:
            parameters.append({
                "id": filtered_result_0_item_filter_1[0],
                "status": "Closed",
                "disposition": "Closed - As part of investigation",
                "finding_time": "",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update finding or investigation", parameters=parameters, name="update_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=add_task_note_2)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["close_findings_prompt:action_result.summary.responses.0", "==", "Yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        related_findings_list(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_task_note_3(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_task_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""Based on the positive response of the user prompt to close findings, all related findings have been closed in the Analyst Queue with Disposition as \"Closed - As part of investigation\". The context of all those individual findings is available in this investigation.\n\n\nAll related findings key information has been added to the \"Events\" tab as evidence.\n\nClosed Findings as part of this Investigation:\n\n\n| Finding ID | Status |\n| --- | --- |\n%%\n| {0} | {1} |\n%%""",
        parameters=[
            "filtered-data:filter_1:condition_1:get_finding_or_investigation_1:action_result.data.*.finding_id",
            "filtered-data:filter_1:condition_1:get_finding_or_investigation_1:action_result.data.*.status_name"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:get_finding_or_investigation_1:action_result.data.*.finding_id","filtered-data:filter_1:condition_1:get_finding_or_investigation_1:action_result.data.*.status_name"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for finding_data_item in finding_data:
        for filtered_result_0_item_filter_1 in filtered_result_0_data_filter_1:
            for get_task_id_1_result_item in get_task_id_1_result_data:
                for get_phase_id_1_result_item in get_phase_id_1_result_data:
                    if finding_data_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and finding_data_item[1] is not None:
                        parameters.append({
                            "id": finding_data_item[0],
                            "title": "Analyst decision to close related findings",
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_2", assets=["builtin_mc_connector"], callback=join_update_task_in_current_phase_1)

    return


@phantom.playbook_block()
def run_query_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""| `risk_event_timeline_search(\"{0}\",\"{1}\")`\n| where _time>={2} AND _time<={3}\n| search eventtype=\"notable\"\n| fields source, source_event_id _time, annotations.mitre_attack, entity, risk_object, normalized_risk_object, threat_object, threat_match_value, risk_message, threat_object_type\n| `add_events({4})`""",
        parameters=[
            "finding:consolidated_findings.normalized_risk_object",
            "finding:consolidated_findings.risk_object_type",
            "finding:consolidated_findings.info_min_time",
            "finding:consolidated_findings.info_max_time",
            "finding:investigation_id"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.normalized_risk_object","finding:consolidated_findings.risk_object_type","finding:consolidated_findings.info_min_time","finding:consolidated_findings.info_max_time","finding:investigation_id"])

    parameters = []

    # build parameters list for 'run_query_2' call
    for finding_data_item in finding_data:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "",
                "display": "source, source_event_id _time, annotations.mitre_attack, entity, risk_object, normalized_risk_object, threat_object, threat_match_value, risk_message, threat_object_type",
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

    phantom.act("run query", parameters=parameters, name="run_query_2", assets=["splunk"])

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
                    "name": "Gather related findings",
                    "order": "",
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
def add_task_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for finding_data_item in finding_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if finding_data_item[0] is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and finding_data_item[1] is not None:
                    parameters.append({
                        "id": finding_data_item[0],
                        "title": "Analyst decision to NOT close related findings",
                        "content": "Based on the negative response of the user prompt to close findings, all related findings have NOT been closed in the Analyst Queue.",
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_3", assets=["builtin_mc_connector"], callback=join_update_task_in_current_phase_1)

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
                "task_name": "Gather related findings",
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

    phantom.act("get task id", parameters=parameters, name="get_task_id_1", assets=["builtin_mc_connector"], callback=run_query_1)

    return


@phantom.playbook_block()
def findings_exist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("findings_exist() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["run_query_1:action_result.summary.total_events", "!=", 0]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        related_findings_note(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_task_note_4(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_task_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_4() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""There are no individual findings in this investigation as it is comprised of only \"Intermediate Findings\".\n\n\nTo review the Intermediate Findings, check the \"Overview\" tab\n""",
        parameters=[])

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_4' call
    for finding_data_item in finding_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if finding_data_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and finding_data_item[1] is not None:
                    parameters.append({
                        "id": finding_data_item[0],
                        "title": "Related Intermediate Findings in the Analyst Queue:",
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_4", assets=["builtin_mc_connector"], callback=join_update_task_in_current_phase_1)

    return


@phantom.playbook_block()
def related_findings_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("related_findings_list() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.source_event_id","run_query_1:action_result.data.*._time"], action_results=results)

    run_query_1_result_item_0 = [item[0] for item in run_query_1_result_data]
    run_query_1_result_item_1 = [item[1] for item in run_query_1_result_data]

    related_findings_list__related_findings_id = None
    related_findings_list__related_findings_time = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(run_query_1_result_item_0)
    phantom.debug(run_query_1_result_item_1)
    related_findings_list__related_findings_id = []
    related_findings_list__related_findings_time = []
    #phantom.debug(run_query_1_result_item_0[0])
    phantom.debug("length of incoming")
    phantom.debug(len(run_query_1_result_item_0))
    for i in range(len(run_query_1_result_item_0)):
        phantom.debug("length of each item")
        phantom.debug(len(run_query_1_result_item_0[i]))
        
        
#        if islist( len([item]) != 1:
#            for i in range(len(item)):
#                related_findings_list__related_findings_id.append(item[0][0][i])
#        else:
#            related_findings_list__related_findings_id.append([item][0])
#    
#    for item in run_query_1_result_item_1:
#        if len([item]) != 1:
#            for i in range(len(item)):
##                related_findings_list__related_findings_time.append(item[0][0][i])
#       else:
#            related_findings_list__related_findings_time.append([item][0])
#            
#    phantom.debug(related_findings_list__related_findings_id)
#    phantom.debug(related_findings_list__related_findings_time)
    #related_findings_list__related_findings_time = []
    #phantom.debug(run_query_1_result_item_1[0])
    #related_findings_list__related_findings_time = run_query_1_result_item_1[0]
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="related_findings_list:related_findings_id", value=json.dumps(related_findings_list__related_findings_id))
    phantom.save_run_data(key="related_findings_list:related_findings_time", value=json.dumps(related_findings_list__related_findings_time))

    return


@phantom.playbook_block()
def id_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("id_list() called")

    related_findings_list__related_findings_id = json.loads(_ if (_ := phantom.get_run_data(key="related_findings_list:related_findings_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": related_findings_list__related_findings_id,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="id_list", callback=time_list)

    return


@phantom.playbook_block()
def time_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("time_list() called")

    related_findings_list__related_findings_time = json.loads(_ if (_ := phantom.get_run_data(key="related_findings_list:related_findings_time")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": related_findings_list__related_findings_time,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="time_list", callback=get_finding_or_investigation_1)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["get_finding_or_investigation_1:action_result.data.*.status_name", "!=", "Closed"]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        update_finding_or_investigation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["get_finding_or_investigation_1:action_result.data.*.status_name", "==", "Closed"]
        ],
        name="filter_1:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        add_task_note_5(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def add_task_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_5() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""| Finding ID | Status |\n| --- | --- |\n%%\n| {0} | {1} |\n%%\n""",
        parameters=[
            "filtered-data:filter_1:condition_2:get_finding_or_investigation_1:action_result.data.*.finding_id",
            "filtered-data:filter_1:condition_2:get_finding_or_investigation_1:action_result.data.*.status_name"
        ])

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_2:get_finding_or_investigation_1:action_result.data.*.finding_id","filtered-data:filter_1:condition_2:get_finding_or_investigation_1:action_result.data.*.status_name"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_5' call
    for finding_data_item in finding_data:
        for filtered_result_0_item_filter_1 in filtered_result_0_data_filter_1:
            for get_task_id_1_result_item in get_task_id_1_result_data:
                for get_phase_id_1_result_item in get_phase_id_1_result_data:
                    if finding_data_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and finding_data_item[1] is not None:
                        parameters.append({
                            "id": finding_data_item[0],
                            "title": "Previously Closed Findings:",
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_5", assets=["builtin_mc_connector"], callback=join_update_task_in_current_phase_1)

    return


@phantom.playbook_block()
def get_finding_or_investigation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_finding_or_investigation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    id_list__result = phantom.collect2(container=container, datapath=["id_list:custom_function_result.data.output"])
    time_list__result = phantom.collect2(container=container, datapath=["time_list:custom_function_result.data.output"])

    parameters = []

    # build parameters list for 'get_finding_or_investigation_1' call
    for id_list__result_item in id_list__result:
        for time_list__result_item in time_list__result:
            if id_list__result_item[0] is not None:
                parameters.append({
                    "id": id_list__result_item[0],
                    "finding_time": time_list__result_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=filter_1)

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