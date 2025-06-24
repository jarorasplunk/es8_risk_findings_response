"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    # call 'refresh_finding_or_investigation_1' block
    get_finding_or_investigation_1(container=container)
    return

@phantom.playbook_block()
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""`notable` | where event_id IN ({0})\n| fields rule_name, event_id, status_label, owner""",
        parameters=[
            "included_findings:custom_function:finding_id"
        ])

    included_findings__finding_id = json.loads(_ if (_ := phantom.get_run_data(key="included_findings:finding_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if query_formatted_string is not None:
        parameters.append({
            "query": query_formatted_string,
            "command": "",
            "display": "rule_name, status_label, owner",
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

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["es"], callback=get_phase_id_1)

    return


@phantom.playbook_block()
def related_findings_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("related_findings_note() called")

    template = """| Detection | Finding | Status | Owner |\n| --- | --- | --- | --- |\n%%\n| {0} | [{1}](https://i-0e6bc36a44836889b.splunk.show/en-GB/app/SplunkEnterpriseSecuritySuite/incident_review?earliest=-30d&latest=now&search={1}) | {2} | {3} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "run_query_1:action_result.data.*.rule_name",
        "run_query_1:action_result.data.*.event_id",
        "run_query_1:action_result.data.*.status_label",
        "run_query_1:action_result.data.*.owner"
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def close_findings_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("close_findings_prompt() called")

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """This Investigation is composed of many related findings and intermediate findings.\n\nYou can browse all these related findings on a risk timeline in the Overview Tab.\n\nPlease select a response below to manage these findings in the Analyst Queue while you continue to work on the investigation.\n\n\n\n{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "open_findings_format:custom_function:open_findings_note"
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

    included_findings__findings_list = json.loads(_ if (_ := phantom.get_run_data(key="included_findings:findings_list")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if included_findings__findings_list is not None:
        parameters.append({
            "id": included_findings__findings_list,
            "status": "Closed",
            "disposition": "disposition:7",
            "finding_time": "",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []

    if included_findings__findings_list is not None:
        for item in included_findings__findings_list:
            parameters.append({
                "id": item,
                "status": "Closed",
                "disposition": "Closed - As part of investigation",
                "finding_time": "",
            })
    phantom.debug(parameters)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update finding or investigation", parameters=parameters, name="update_finding_or_investigation_1", assets=["builtin_mc_connector"])

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
        update_event_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def add_task_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""Based on the positive response of the user prompt to close findings, all related findings have been closed in the Analyst Queue with Disposition as \"Closed - As part of investigation\". The context of all those individual findings is available in this investigation.\n\nThere may be other \"Intermediate Findings\" contributing to this investigation, please review them in the Overview tab""",
        parameters=[
            "included_findings:custom_function:findings_list"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    included_findings__findings_list = json.loads(_ if (_ := phantom.get_run_data(key="included_findings:findings_list")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": "Analyst decision to close related findings",
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_2", assets=["builtin_mc_connector"], callback=update_task_in_current_phase_1)

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
def add_task_note_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_6() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    refresh_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["refresh_finding_or_investigation_1:action_result.data.*.data.investigation_id","refresh_finding_or_investigation_1:action_result.data.*.data.response_plans.*.id","refresh_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_6' call
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_6", assets=["builtin_mc_connector"])

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
def add_task_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_4() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""Below is the summary of included Findings in this Investigation (Intermediate Findings, check the \"Overview\" tab)\n\n{0}\n\n\n\n\n\nCheck the \"Prompt\" to see if there are related Findings that are not \"Closed\" in the Analyst Queue.\n\nIf all the related findings are already \"Closed\", there will be no requests in the \"Prompt\"\n\n\n\n\nMessage prompt name: close_findings_prompt""",
        parameters=[
            "related_findings_note:formatted_data"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    related_findings_note = phantom.get_format_data(name="related_findings_note")

    parameters = []

    # build parameters list for 'add_task_note_4' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": "Related Findings in the Analyst Queue:",
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_4", assets=["builtin_mc_connector"])

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

    phantom.custom_function(custom_function="community/list_demux", parameters=parameters, name="time_list")

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

    phantom.act("refresh finding or investigation", parameters=parameters, name="refresh_finding_or_investigation_1", assets=["builtin_mc_connector"])

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

    phantom.act("update task in current phase", parameters=parameters, name="update_task_in_current_phase_2", assets=["builtin_mc_connector"], callback=related_findings_status_filter)

    return


@phantom.playbook_block()
def included_findings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("included_findings() called")

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.consolidated_findings_map._raw"], action_results=results)

    get_finding_or_investigation_1_result_item_0 = [item[0] for item in get_finding_or_investigation_1_result_data]

    included_findings__finding_id = None
    included_findings__intermediate_finding_id = None
    included_findings__findings_list = None

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

    included_findings__findings_list = final_result["finding_ids"]
    included_findings__finding_id = final_result["finding_ids"]
    included_findings__intermediate_finding_id = final_result["intermediate_finding_ids"]
    
    included_findings__finding_id = str(included_findings__finding_id).replace("[","").replace("]","").replace("'","\"")
    included_findings__intermediate_finding_id = str(included_findings__intermediate_finding_id).replace("[","").replace("]","").replace("'","\"")
    
    phantom.debug(included_findings__finding_id)
    phantom.debug(included_findings__intermediate_finding_id)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="included_findings__inputs:0:get_finding_or_investigation_1:action_result.data.*.consolidated_findings_map._raw", value=json.dumps(get_finding_or_investigation_1_result_item_0))

    phantom.save_block_result(key="included_findings:finding_id", value=json.dumps(included_findings__finding_id))
    phantom.save_block_result(key="included_findings:intermediate_finding_id", value=json.dumps(included_findings__intermediate_finding_id))
    phantom.save_block_result(key="included_findings:findings_list", value=json.dumps(included_findings__findings_list))

    run_query_1(container=container)

    return


@phantom.playbook_block()
def format_findings_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_findings_query() called")

    template = """`notable` | where event_id IN (\"{0}\")\n"""

    # parameter list for template variable replacement
    parameters = [
        "included_findings_values:custom_function_result.data.output"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_findings_query")

    return


@phantom.playbook_block()
def update_finding_or_investigation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_finding_or_investigation_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    included_findings__findings_list = json.loads(_ if (_ := phantom.get_run_data(key="included_findings:findings_list")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if included_findings__findings_list is not None:
        parameters.append({
            "id": included_findings__findings_list,
            "status": "Closed",
            "disposition": "disposition:7",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    phantom.debug(included_findings__findings_list)
    
    for item in included_findings__findings_list:
        phantom.debug(item)
        parameters.append({
            "id": item,
            "status": "Closed",
            "disposition": "disposition:7",
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update finding or investigation", parameters=parameters, name="update_finding_or_investigation_2", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def playbook_close_related_findings_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_close_related_findings_1() called")

    included_findings__findings_list = json.loads(_ if (_ := phantom.get_run_data(key="included_findings:findings_list")) != "" else "null")  # pylint: disable=used-before-assignment

    inputs = {
        "findings_list": included_findings__findings_list,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "es8_risk_findings_response/close_related_findings", returns the playbook_run_id
    playbook_run_id = phantom.playbook("es8_risk_findings_response/close_related_findings", container=container, name="playbook_close_related_findings_1", callback=playbook_close_related_findings_1_callback, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_close_related_findings_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_close_related_findings_1_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


@phantom.playbook_block()
def update_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_event_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    open_findings_format__open_finding_ids = json.loads(_ if (_ := phantom.get_run_data(key="open_findings_format:open_finding_ids")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if open_findings_format__open_finding_ids is not None:
        parameters.append({
            "status": 5,
            "event_ids": open_findings_format__open_finding_ids,
            "disposition": "",
            "integer_disposition": 7,
            "wait_for_confirmation": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_event_1", assets=["es"], callback=decision_2)

    return


@phantom.playbook_block()
def related_findings_status_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("related_findings_status_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["run_query_1:action_result.data.*.status_label", "!=", "Resolved"],
            ["run_query_1:action_result.data.*.status_label", "!=", "Closed"]
        ],
        conditions_dps=[
            ["run_query_1:action_result.data.*.status_label", "!=", "Resolved"],
            ["run_query_1:action_result.data.*.status_label", "!=", "Closed"]
        ],
        name="related_findings_status_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        open_findings_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["run_query_1:action_result.data.*.status_label", "==", "Closed"],
            ["run_query_1:action_result.data.*.status_label", "==", "Resolved"]
        ],
        conditions_dps=[
            ["run_query_1:action_result.data.*.status_label", "==", "Closed"],
            ["run_query_1:action_result.data.*.status_label", "==", "Resolved"]
        ],
        name="related_findings_status_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        closed_findings(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def add_task_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_task_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    content_formatted_string = phantom.format(
        container=container,
        template="""Findings that are already Closed Findings and are related to this investigation:\n\n{0}""",
        parameters=[
            "closed_findings:formatted_data"
        ])

    get_finding_or_investigation_1_result_data = phantom.collect2(container=container, datapath=["get_finding_or_investigation_1:action_result.data.*.investigation_id","get_finding_or_investigation_1:action_result.data.*.response_plans.*.id","get_finding_or_investigation_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_task_id_1_result_data = phantom.collect2(container=container, datapath=["get_task_id_1:action_result.data.*.task_id","get_task_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    get_phase_id_1_result_data = phantom.collect2(container=container, datapath=["get_phase_id_1:action_result.data.*.phase_id","get_phase_id_1:action_result.parameter.context.artifact_id"], action_results=results)
    closed_findings = phantom.get_format_data(name="closed_findings")

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for get_finding_or_investigation_1_result_item in get_finding_or_investigation_1_result_data:
        for get_task_id_1_result_item in get_task_id_1_result_data:
            for get_phase_id_1_result_item in get_phase_id_1_result_data:
                if get_finding_or_investigation_1_result_item[0] is not None and content_formatted_string is not None and get_task_id_1_result_item[0] is not None and get_phase_id_1_result_item[0] is not None and get_finding_or_investigation_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_finding_or_investigation_1_result_item[0],
                        "title": "Closed Findings",
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

    phantom.act("add task note", parameters=parameters, name="add_task_note_3", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def format_closed_findings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_closed_findings() called")

    template = """| Detection | Finding | Status | Owner |\n| --- | --- | --- | --- |\n%%\n| {0} | [{1}](https://i-0e6bc36a44836889b.splunk.show/en-GB/app/SplunkEnterpriseSecuritySuite/incident_review?earliest=-30d&latest=now&search={1}) | {2} | {3} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.rule_name",
        "filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.event_id",
        "filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.status_label",
        "filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.owner"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_closed_findings")

    return


@phantom.playbook_block()
def open_findings_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("open_findings_1() called")

    template = """| Detection | Finding | Status | Owner |\n| --- | --- | --- | --- |\n%%\n| {0} | [{1}](https://i-0e6bc36a44836889b.splunk.show/en-GB/app/SplunkEnterpriseSecuritySuite/incident_review?earliest=-30d&latest=now&event_id={1}) | {2} | {3} |\n%%\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.rule_name",
        "filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.event_id",
        "filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.status_label",
        "filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.owner"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="open_findings_1")

    open_findings_format(container=container)

    return


@phantom.playbook_block()
def closed_findings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("closed_findings() called")

    template = """| Detection | Finding | Status | Owner |\n| --- | --- | --- | --- |\n%%\n| {0} | [{1}](https://i-0e6bc36a44836889b.splunk.show/en-GB/app/SplunkEnterpriseSecuritySuite/incident_review?earliest=-30d&latest=now&search={1}) | {2} | {3} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:related_findings_status_filter:condition_2:run_query_1:action_result.data.*.rule_name",
        "filtered-data:related_findings_status_filter:condition_2:run_query_1:action_result.data.*.event_id",
        "filtered-data:related_findings_status_filter:condition_2:run_query_1:action_result.data.*.status_label",
        "filtered-data:related_findings_status_filter:condition_2:run_query_1:action_result.data.*.owner"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="closed_findings")

    add_task_note_3(container=container)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["update_event_1:action_result.status", "==", "success"]
        ],
        conditions_dps=[
            ["update_event_1:action_result.status", "==", "success"]
        ],
        name="decision_2:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_task_note_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def open_findings_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("open_findings_format() called")

    filtered_result_0_data_related_findings_status_filter = phantom.collect2(container=container, datapath=["filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.rule_name","filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.event_id","filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.status_label","filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.owner"])

    filtered_result_0_data___rule_name = [item[0] for item in filtered_result_0_data_related_findings_status_filter]
    filtered_result_0_data___event_id = [item[1] for item in filtered_result_0_data_related_findings_status_filter]
    filtered_result_0_data___status_label = [item[2] for item in filtered_result_0_data_related_findings_status_filter]
    filtered_result_0_data___owner = [item[3] for item in filtered_result_0_data_related_findings_status_filter]

    open_findings_format__open_findings_note = None
    open_findings_format__open_finding_ids = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    open_findings_format__open_finding_ids = []
    if filtered_result_0_data_related_findings_status_filter:
        note = (
            "\n**Below are the list of open findings related to this investigation.**\n"
            "| Rule name | Finding | Status | Owner |\n"
            "| :--- | :--- | :--- | :--- |\n"
        )
        for rule_name,event_id,status,owner in zip(filtered_result_0_data___rule_name,filtered_result_0_data___event_id,filtered_result_0_data___status_label,filtered_result_0_data___owner):
            #rule_name = rule_name.replace('\n','')
            #event_id = event_id.replace('\n','')
            finding_url = "https://i-0e6bc36a44836889b.splunk.show/en-GB/app/SplunkEnterpriseSecuritySuite/incident_review?earliest=-30d&latest=now&event_id=" + event_id
            #status = status.replace('\n','')
            #owner = owner.replace('\n','')
            phantom.debug(finding_url)
            phantom.debug(status)
            if status != "Closed" or status != "Resolved":
                phantom.debug(finding_url)
                phantom.debug(status)
                note += "|{}|[{}]({})|{}|{}|\n".format(rule_name, event_id, finding_url, status, owner)
                open_findings_format__open_finding_ids.append(event_id)

        open_findings_format__open_findings_note = note
    else:
        open_findings_format__open_findings_note = "\n\n**No open findings found in the investigation in last 30 days**\n"    


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="open_findings_format__inputs:0:filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.rule_name", value=json.dumps(filtered_result_0_data___rule_name))
    phantom.save_block_result(key="open_findings_format__inputs:1:filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.event_id", value=json.dumps(filtered_result_0_data___event_id))
    phantom.save_block_result(key="open_findings_format__inputs:2:filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.status_label", value=json.dumps(filtered_result_0_data___status_label))
    phantom.save_block_result(key="open_findings_format__inputs:3:filtered-data:related_findings_status_filter:condition_1:run_query_1:action_result.data.*.owner", value=json.dumps(filtered_result_0_data___owner))

    phantom.save_block_result(key="open_findings_format:open_findings_note", value=json.dumps(open_findings_format__open_findings_note))
    phantom.save_block_result(key="open_findings_format:open_finding_ids", value=json.dumps(open_findings_format__open_finding_ids))

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