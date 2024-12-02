"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'debug_1' block
    debug_1(container=container)

    return

@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    finding_data = phantom.collect2(container=container, datapath=["finding:consolidated_findings.risk_object","finding:consolidated_findings.threat_object","finding:consolidated_findings.all_risk_objects"])

    finding_consolidated_findings_risk_object = [item[0] for item in finding_data]
    finding_consolidated_findings_threat_object = [item[1] for item in finding_data]
    finding_consolidated_findings_all_risk_objects = [item[2] for item in finding_data]

    parameters = []

    parameters.append({
        "input_1": finding_consolidated_findings_risk_object,
        "input_2": finding_consolidated_findings_threat_object,
        "input_3": finding_consolidated_findings_all_risk_objects,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

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