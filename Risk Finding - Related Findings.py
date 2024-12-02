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
        template="""| `risk_event_timeline_search(\"{0}\",\"{1}\")` \n| eval earliest={2} \n| eval latest={3} \n| search eventtype=\"notable\" \n| stats count(source_event_id) as source_event_id_count, values(source_event_id) as source_event_id, values(annotations.mitre_attack) as annotations.mitre_attack, values(entity) as entity, values(risk_object) as risk_object, values(normalized_risk_object) as normalized_risk_object, values(threat_object) as threat_object, values(risk_message) as risk_message, values(threat_object_type) as threat_object_type, values(_time) as _time by source\n| `add_events({4})`""",
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

    template = """| Detection | Count |\n| --- | --- |\n%%\n| {0} | {1} |\n%%\n\n\n\n*Follow the prompt to manage these related findings in the Analyst Queue.*"""

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

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*._time","run_query_1:action_result.parameter.context.artifact_id"], action_results=results)
    related_findings_list__related_findings = json.loads(_ if (_ := phantom.get_run_data(key="related_findings_list:related_findings")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'update_finding_or_investigation_1' call
    for run_query_1_result_item in run_query_1_result_data:
        if related_findings_list__related_findings is not None:
            parameters.append({
                "id": related_findings_list__related_findings,
                "status": "Closed",
                "disposition": "Closed - As part of investigation",
                "finding_time": run_query_1_result_item[0],
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
        template="""Based on the positive response of the user prompt to close findings, all related findings have been closed in the Analyst Queue with Disposition as \"Closed - As part of investigation\". The context of all those individual findings is available in this investigation.\n\n\nAll related findings key information has been added to the \"Events\" tab as evidence.\n""",
        parameters=[])

    finding_data = phantom.collect2(container=container, datapath=["finding:investigation_id","finding:response_plans.*.id"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for finding_data_item in finding_data:
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

    if phantom.completed(action_names=["add_task_note_4"]):
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

    phantom.act("update task in current phase", parameters=parameters, name="update_task_in_current_phase_1", assets=["builtin_mc_connector"], callback=gather_entities_and_indicators)

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
def gather_entities_and_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("gather_entities_and_indicators() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.threat_object_type","run_query_1:action_result.data.*.threat_object","run_query_1:action_result.data.*.risk_object_type","run_query_1:action_result.data.*.risk_object"], action_results=results)

    run_query_1_result_item_0 = [item[0] for item in run_query_1_result_data]
    run_query_1_result_item_1 = [item[1] for item in run_query_1_result_data]
    run_query_1_result_item_2 = [item[2] for item in run_query_1_result_data]
    run_query_1_result_item_3 = [item[3] for item in run_query_1_result_data]

    gather_entities_and_indicators__entities = None
    gather_entities_and_indicators__indicators = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    seen = set()
    gather_entities_and_indicators__entities = []
    
    for pair in list(zip(run_query_1_result_item_2,run_query_1_result_item_3)):
        if pair not in seen:  # Check if the pair is already added
            gather_entities_and_indicators__entities.append(pair)
            seen.add(pair)

    seen = set()
    gather_entities_and_indicators__indicators = []
    for pair in list(zip(run_query_1_result_item_0,run_query_1_result_item_1)):
        if pair not in seen:  # Check if the pair is already added
            gather_entities_and_indicators__indicators.append(pair)
            seen.add(pair)
    
    #gather_entities_and_indicators__entities = list(set(zip(run_query_2_result_item_2,run_query_2_result_item_3)))
    #gather_entities_and_indicators__indicators = list(set(zip(run_query_2_result_item_0,run_query_2_result_item_1)))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="gather_entities_and_indicators:entities", value=json.dumps(gather_entities_and_indicators__entities))
    phantom.save_run_data(key="gather_entities_and_indicators:indicators", value=json.dumps(gather_entities_and_indicators__indicators))

    playbook_risk_finding___enrich_findings_1(container=container)

    return


@phantom.playbook_block()
def playbook_risk_finding___enrich_findings_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_risk_finding___enrich_findings_1() called")

    gather_entities_and_indicators__entities = json.loads(_ if (_ := phantom.get_run_data(key="gather_entities_and_indicators:entities")) != "" else "null")  # pylint: disable=used-before-assignment
    gather_entities_and_indicators__indicators = json.loads(_ if (_ := phantom.get_run_data(key="gather_entities_and_indicators:indicators")) != "" else "null")  # pylint: disable=used-before-assignment

    inputs = {
        "entities": gather_entities_and_indicators__entities,
        "indicators": gather_entities_and_indicators__indicators,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "es8_risk_findings_response/Risk Finding - Enrich Findings", returns the playbook_run_id
    playbook_run_id = phantom.playbook("es8_risk_findings_response/Risk Finding - Enrich Findings", container=container, inputs=inputs)

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
    related_findings_list__related_findings_id = []
    for item in run_query_1_result_item_0[0]:
        related_findings_list__related_findings_id.append(item)
    
    related_findings_list__related_findings_time = []
    related_findings_list__related_findings_time = run_query_1_result_item_1[0]
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="related_findings_list:related_findings_id", value=json.dumps(related_findings_list__related_findings_id))
    phantom.save_run_data(key="related_findings_list:related_findings_time", value=json.dumps(related_findings_list__related_findings_time))

    update_finding_or_investigation_1(container=container)

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