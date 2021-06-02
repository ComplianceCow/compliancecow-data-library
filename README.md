![N|Solid](https://partner.compliancecow.live/assets/images/cow/cowlogo2.png)

# What is ComplianceCow?

ComplianceCow automates controls testing for Security Compliance for applications running on cloud and kubernetes. If you are a first time user, please refer the [ComplianceCow Integration](https://partner.compliancecow.live/ui/documentation) Guide which shall set the context and provide a high level overview of how ComplianceCow works.

# ComplianceCow Data Library

 The data library exposes all of the ComplianceCow data and metadata so that our customers and users can build models, create custom reports or simply use as signals to enrich security posture. We are publishing the data library and the instructions to install. We are also publishing a sample notebook that has the methods used in the data library for consuming data, metadata and reports.

## Installing ComplianceCow Data Library

We recommend that you activate [pyenv](https://github.com/pyenv/pyenv) before you install ComplianceCow. ComplianceCow requires [Python](https://www.python.org/) v3.7+ to run.

### Installing the ComplainceCow Data Library package from source

Git clone this repo and change into the compliancecow directory

```sh
git clone https://github.com/ContiNube/compliancecow-data-library.git
cd compliancecow
```

Install the library

```sh
pip install .
```

### Using the ComplianceCow Data Library

Now that you have installed your library, you are ready to use. You can look at the reference notebook file for step by step commands of accessing the data and metadata from the ComplianceCow system.

The first step is to create a ComplianceCow client. You can get the client handle by passing the valid credentials for ComplianceCow in the method constructor (if you have any questions, reach us at [Info@Compliancecow.com](mailto:info@compliancecow.com)

```sh
from compliancecow.models import cowlib
client = cowlib.Client(auth_token=<auth_token>)
```

With the client handle, you can now iterate through the ComplianceCow hierarchy to fetch data and metadata. Refer to the sections above on [Operating a Plan]() and [Reporting]() to understand the hierarchy of objects in ComplianceCow.

As the next step, you can fetch the specific (or all) plans in ComplianceCow through the get_plans() method. You can pass one or more Plan IDs (if you know 'em) to fetch those specific plans.

```sh
plans, errors = client.get_plans(ids=[<plan id1>, <plan_id2> ...])
```

Each client method returns an errors object, in addition to the object being fetched. This will allow you to check for errors (or raise errors) and take corrective actions before you move to the next methods.

Once you know your Plan IDs that you are interested with, you can now select the data for Plan Instances (a.k.a Plan Runs). In the case below, we are getting ALL the plan instances for a specific plan that we got with the earlier get_plans() method

```sh
plan_instances, errors = client.get_plan_instances(plan=plans[0])
```

You can iterate through the plan instances object and identify a specific Plan Instance that you want to operate on

```sh
plan_instance = plan_instances[0]
```

Each Plan Instance is an operating unit and contains information on controls, evidences, checklists, notes etc. Once you identify the plan instance, as in the previous step, you can select the next iteration of objects such as controls.

```sh
controls = plan_instance.get_plan_instance_controls(having_evidences=True)
```

The get_plan_instance_controls() method also takes in an optional parameter that filters for those sub controls that only have evidences.
Note: This does not represented the nested structure controls but a flat listing of all leaf (executable) sub controls in the given plan instance.

You can now access all objects that are represented inside of the controls. The following are the list of methods that are available for accessing control metadata, checklists, notes, attachments and importantly, evidences.

For example, you can iterate through all the evidence objects inside the control within a plan instance. Once you identify a particular evidence, say the first one, you can fetch the entire evidence data as a dataframe by executing the below method.

```sh
data, errors = client.get_evidence_data(evidence=controls[0].evidences[0])
```

If you want to understand the current configurations that are present ```Plan + Configuration = Plan Instance``` then you can simply use the client to get_configurations()

```sh
configurations, error = client.get_configurations() 
```

