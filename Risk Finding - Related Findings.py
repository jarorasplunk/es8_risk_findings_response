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
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template=""" | where event_id IN ({0})""",
        parameters=[
            "included_findings_values:custom_function_result.data.output"
        ])

    included_findings_values__result = phantom.collect2(container=container, datapath=["included_findings_values:custom_function_result.data.output"])

    parameters = []

    # build parameters list for 'run_query_1' call
    for included_findings_values__result_item in included_findings_values__result:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "`notable`",
                "display": "",
                "end_time": "",
                "start_time": "",
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

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["splunk"])

    return


@phantom.playbook_block()
def related_findings_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("related_findings_note() called")

    template = """| Detection Name| Finding ID |\n| --- | --- |\n%%\n| {0} | [{1}](https://es8-shw-46d5351519c4f2.stg.splunkcloud.com/en-GB/app/SplunkEnterpriseSecuritySuite/incident_review?earliest=--7d%40h&latest=now&search={1}) |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "run_query_1:action_result.data.*.source",
        "run_query_1:action_result.data.*.source_event_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="related_findings_note")

    return


@phantom.playbook_block()
def add_task_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""{0}\n\n\n\nFollow the prompt to manage these related findings in the Analyst Queue.\n\nMessage prompt name: close_findings_prompt""",
        parameters=[
            "related_findings_note:formatted_data"
        ])

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.data.*.data.response_plans.*.id","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    related_findings_note = phantom.get_format_data(name="related_findings_note")

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if refresh_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and refresh_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": refresh_finding_or_investigation_1_result_item[0],
                        "title": "Related Findings in the Analyst Queue:",
                        "content": content_formatted_string,
                        "task_id": get_task_id_1_result_item[0],
                        "phase_id": get_phase_id_1_result_item[0],
                        "response_plan_id": refresh_finding_or_investigation_1_result_item[1],
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

    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:get_finding_or_investigation_2:action_result.data.*.finding_id"])

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
        conditions_dps=[
            ["close_findings_prompt:action_result.summary.responses.0", "==", "Yes"]
        ],
        name="decision_1:condition_1",
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
        template="""Based on the positive response of the user prompt to close findings, all related findings have been closed in the Analyst Queue with Disposition as \"Closed - As part of investigation\". The context of all those individual findings is available in this investigation.\n\n\nAll related findings key information has been added to the \"Events\" tab as evidence.\n\nClosed Findings as part of this Investigation:\n\n\n| Finding ID | Status |\n| --- | --- |\n%%\n| {0} | Closed |\n%%\n\n\n\nThere may be other \"Intermediate Findings\" contributing to this investigation, please review them in the Overview tab""",
        parameters=[
            "filtered-data:filter_1:condition_1:get_finding_or_investigation_2:action_result.data.*.finding_id"
        ])

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.data.*.data.response_plans.*.id","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:get_finding_or_investigation_2:action_result.data.*.finding_id"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
        for filtered_result_0_item_filter_1 in filtered_result_0_data_filter_1:
            for get_task_id_1_result_item in get_task_id_1_result_data:
                for get_phase_id_1_result_item in get_phase_id_1_result_data:
                    if refresh_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and refresh_finding_or_investigation_1_result_item[1] is not None:
                        parameters.append({
                            "id": refresh_finding_or_investigation_1_result_item[0],
                            "title": "Analyst decision to close related findings",
                            "content": content_formatted_string,
                            "task_id": get_task_id_1_result_item[0],
                            "phase_id": get_phase_id_1_result_item[0],
                            "response_plan_id": refresh_finding_or_investigation_1_result_item[1],
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

    if phantom.completed(action_names=["add_task_note_2", "add_task_note_3", "add_task_note_4", "add_task_note_5"]):
        # call connected block "update_task_in_current_phase_1"
        update_task_in_current_phase_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def update_task_in_current_phase_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_task_in_current_phase_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_task_in_current_phase_1' call
    for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            if refresh_finding_or_investigation_1_result_item[0] is not None and get_task_id_1_result_item[0] is not None:
                parameters.append({
                    "id": refresh_finding_or_investigation_1_result_item[0],
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

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.data.*.data.response_plans.*.id","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if refresh_finding_or_investigation_1_result_item[0] is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and refresh_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": refresh_finding_or_investigation_1_result_item[0],
                        "title": "Analyst decision to NOT close related findings",
                        "content": "Based on the negative response of the user prompt to close findings, all related findings have NOT been closed in the Analyst Queue.",
                        "task_id": get_task_id_1_result_item[0],
                        "phase_id": get_phase_id_1_result_item[0],
                        "response_plan_id": refresh_finding_or_investigation_1_result_item[1],
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
                "task_name": "Gather related findings",
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

    phantom.act("get task id", parameters=parameters, name="get_task_id_1", assets=["builtin_mc_connector"], callback=update_task_in_current_phase_2)

    return


@phantom.playbook_block()
def findings_exist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("findings_exist() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_finding_or_investigation_5:action_result.data.*.finding_id", "!=", 0]
        ],
        conditions_dps=[
            ["get_finding_or_investigation_5:action_result.data.*.finding_id", "!=", 0]
        ],
        name="findings_exist:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    return


@phantom.playbook_block()
def add_task_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_4() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""There are no individual findings in this investigation as it is comprised of only \"Intermediate Findings\".\n\n\nTo review the Intermediate Findings, check the \"Overview\" tab\n""",
        parameters=[])

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.data.*.data.response_plans.*.id","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_4' call
    for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if refresh_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and refresh_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": refresh_finding_or_investigation_1_result_item[0],
                        "title": "Related Intermediate Findings in the Analyst Queue:",
                        "content": content_formatted_string,
                        "task_id": get_task_id_1_result_item[0],
                        "phase_id": get_phase_id_1_result_item[0],
                        "response_plan_id": refresh_finding_or_investigation_1_result_item[1],
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
    related_findings_list__related_findings_time = []
    
    for item in run_query_1_result_item_0:
        phantom.debug(item)
        if isinstance(item, list):
            for id in item:
                related_findings_list__related_findings_id.append(id)
        else:
            related_findings_list__related_findings_id.append(item)
    
    for item in run_query_1_result_item_1:
        phantom.debug(item)
        if isinstance(item, list):
            for id in item:
                related_findings_list__related_findings_time.append(id)
        else:
            related_findings_list__related_findings_time.append(item)
    phantom.debug(related_findings_list__related_findings_id)
    phantom.debug(related_findings_list__related_findings_time)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="related_findings_list__inputs:0:run_query_1:action_result.data.*.source_event_id", value=json.dumps(run_query_1_result_item_0))
    phantom.save_block_result(key="related_findings_list__inputs:1:run_query_1:action_result.data.*._time", value=json.dumps(run_query_1_result_item_1))

    phantom.save_block_result(key="related_findings_list:related_findings_id", value=json.dumps(related_findings_list__related_findings_id))
    phantom.save_block_result(key="related_findings_list:related_findings_time", value=json.dumps(related_findings_list__related_findings_time))

    id_list(container=container)

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

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="time_list", callback=get_finding_or_investigation_2)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["get_finding_or_investigation_2:action_result.data.*.status_name", "!=", "Closed"],
            ["get_finding_or_investigation_2:action_result.data.*.finding_id", "!=", ""]
        ],
        conditions_dps=[
            ["get_finding_or_investigation_2:action_result.data.*.status_name", "!=", "Closed"],
            ["get_finding_or_investigation_2:action_result.data.*.finding_id", "!=", ""]
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
            ["get_finding_or_investigation_2:action_result.data.*.status_name", "==", "Closed"]
        ],
        conditions_dps=[
            ["get_finding_or_investigation_2:action_result.data.*.status_name", "==", "Closed"]
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
            "filtered-data:filter_1:condition_2:get_finding_or_investigation_2:action_result.data.*.finding_id",
            "filtered-data:filter_1:condition_2:get_finding_or_investigation_2:action_result.data.*.status_name"
        ])

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.data.*.data.response_plans.*.id","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    filtered_result_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_2:get_finding_or_investigation_2:action_result.data.*.finding_id","filtered-data:filter_1:condition_2:get_finding_or_investigation_2:action_result.data.*.status_name"])
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_5' call
    for refresh_finding_or_investigation_1_result_item in refresh_finding_or_investigation_1_result_data:
        for filtered_result_0_item_filter_1 in filtered_result_0_data_filter_1:
            for get_task_id_1_result_item in get_task_id_1_result_data:
                for get_phase_id_1_result_item in get_phase_id_1_result_data:
                    if refresh_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and refresh_finding_or_investigation_1_result_item[1] is not None:
                        parameters.append({
                            "id": refresh_finding_or_investigation_1_result_item[0],
                            "title": "Previously or Already Closed Findings:",
                            "content": content_formatted_string,
                            "task_id": get_task_id_1_result_item[0],
                            "phase_id": get_phase_id_1_result_item[0],
                            "response_plan_id": refresh_finding_or_investigation_1_result_item[1],
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
def get_finding_or_investigation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_finding_or_investigation_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    id_list__result = phantom.collect2(container=container, datapath=["id_list:custom_function_result.data.output"])

    parameters = []

    # build parameters list for 'get_finding_or_investigation_2' call
    for id_list__result_item in id_list__result:
        if id_list__result_item[0] is not None:
            parameters.append({
                "id": id_list__result_item[0],
                "finding_time": "",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(related_findings_list__related_findings_id)
    #phantom.debug(related_findings_list__related_findings_time)
    #parameters = []
    #for i in range(len(related_findings_list__related_findings_id)):
    #    parameters.append({
    #        "id": related_findings_list__related_findings_id[i],
    #        "finding_time": related_findings_list__related_findings_time[i],
    #    })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_2", assets=["builtin_mc_connector"], callback=filter_1)

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
                "map_consolidated_findings": 1,
                "finding_time": "",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get finding or investigation", parameters=parameters, name="get_finding_or_investigation_1", assets=["builtin_mc_connector"], callback=included_findings)

    return


@phantom.playbook_block()
def update_task_in_current_phase_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_task_in_current_phase_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_task_in_current_phase_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            if get_finding_or_investigation_1_result_item[0] is not None and get_task_id_1_result_item[0] is not None:
                parameters.append({
                    "id": get_finding_or_investigation_1_result_item[0],
                    "name": "Gather related findings",
                    "status": "Started",
                    "task_id": get_task_id_1_result_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update task in current phase", parameters=parameters, name="update_task_in_current_phase_2", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def included_findings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("included_findings() called")

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.consolidated_findings_map._raw"], action_results=results)

    get_finding_or_investigation_1_result_item_0 = [item[0] for item in get_finding_or_investigation_1_result_data]

    included_findings__finding_id = None
    included_findings__intermediate_finding_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(get_finding_or_investigation_1_result_item_0)
    #phantom.debug(type(get_finding_or_investigation_1_result_item_0))
    import json
    import re

    included_findings__finding_id = []
    included_findings__intermediate_finding_id = []
    final_result = {
        "finding_ids": [],
        "intermediate_finding_ids": []
    }

    # Loop through each dictionary in the list
    for item in get_finding_or_investigation_1_result_item_0:
        for long_key_string in item.keys():
            matches = re.findall(r'(\w+)="(.*?)"', long_key_string)
            for key, value in matches:
                if key in ["finding_ids", "intermediate_finding_ids"]:
                    final_result[key].append(value)

    phantom.debug(json.dumps(final_result, indent=2))

    finding_id = final_result["finding_ids"]
    for id in finding_id:
        included_findings__finding_id.append(id)
        
    intermediate_finding_id = final_result["intermediate_finding_ids"]
    for id in intermediate_finding_id:
        included_findings__intermediate_finding_id.append(id)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="included_findings__inputs:0:get_finding_or_investigation_1:action_result.data.*.consolidated_findings_map._raw", value=json.dumps(get_finding_or_investigation_1_result_item_0))

    phantom.save_block_result(key="included_findings:finding_id", value=json.dumps(included_findings__finding_id))
    phantom.save_block_result(key="included_findings:intermediate_finding_id", value=json.dumps(included_findings__intermediate_finding_id))

    included_findings_values(container=container)

    return


@phantom.playbook_block()
def included_findings_values(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("included_findings_values() called")

    included_findings__finding_id = json.loads(_ if (_ := phantom.get_run_data(key="included_findings:finding_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "input_list": included_findings__finding_id,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="included_findings_values", callback=run_query_1)

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