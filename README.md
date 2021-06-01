![N|Solid](https://partner.compliancecow.live/assets/images/cow/cowlogo2.png)

# What is ComplianceCow? High level overview of how it works

ComplianceCow automates controls testing for Security Compliance for applications running on cloud and kubernetes.If you are first time user, please do a quick read on the ComplianceCow operations below. If you already know or have no patience to read through :), please skip to the ComplianceCow Data Library section

## Create a Configuration

The Configuration flow specifies the services in Azure that the user integrates with in order to evaluate the security posture, collect evidences and report. The Configuration flow can vary dependent on the plan selected (more about the "plan" below)

+ User creates a configuration in ComplianceCow with required credentials. For Azure, the user can provide a list of Azure Subscriptions Client ID, Client Secret and the Subscription ID. For Azure Kubernetes Services, the user, in addition to specifying the subscriptions, can specify one or more clusters: private or public. The user will need to provide access to a kubectl instance (VM) that has access to the private or public cluster
+ ComplianceCow will auto discover services for Azure and Kubernetes. For Azure, ComplianceCow will determine Resource Groups, Virtual Networks and Subnets. Specificallly for AKS, the system will automatically enumerate all the namespaces for the selected cluster. The user can specify the scope by selecting one or more of these elements such as Resource Groups, VNETs, Clusters; as applicable

## Executing a Plan

A Plan in ContiNube is a collection of security controls such as PCI-DSS and CIS Benchmark. It is made up of the hierarchical set of controls. Each control can be automated; i.e, automatically collects evidences from the underlying Azure and/or AKS services or can be manual.

In order to execute a plan, the user

+ Selects a configuration
+ Enters the control duration or sampling period
+ Provide run time user inputs, if any
+ Execute

This adds a ticket to the execution queue and the ComplianceCow system automatically connects with the services in scope and collects data, evidences and testing results

## Operating a Plan

The following describes the hierarchical structure of a plan:

+ Plan
  + Control (i)
    + Control Metadata such as Ownership, Due Date, Priority
    + Subcontrol (i.1)
      + Subcontrol Medadata such as Ownership, Due Date, Priority. By default takes the same values as that of the parent control
      + Checklist (0 .. n): User can create one or more To-do lists
      + Note (0 .. n): User can create one or more notes
      + Attachment (0 .. n)
      + Evidence (0 .. n): There can be one or more evidences. These evidences can be automated or manual. When ComplianceCow automatically fetches evidences from Azure or AKS services, they go here. The user can also manually upload evidence files. An evidence file in ComplianceCow has 3 components
        + Data file: This file contains the data generated in a common data model from the services. For example, there is a file for all entries in Network Security Group for the selected scope in azure subscriptions. This file is typically in parquet format in ComplianceCow
        + Meta file: This file is an index file that contains all the metadata for the rows in the corresponding data file. For example, the meta file may contain a record that indicates the status of a record. If a row is deleted in the data file, ComplianceCow does not change the data file but instead maintains a marker in the meta file
        + Column file: This file contains the metadata information for each field in the data file. For example, it holds the data type of columns in the data file
        All files; Data, Meta and Column are versioned controlled for each commit in ComplianceCow. Any save of these files are saved on to the user workspace and are not moved to the version control system until the commits happen.
    + Subcontrol (i.2) .....
  + Control (ii) ...

Each Control, Subcontrol, Checklist, Evidence can be assigned to one or more users. ComplianceCow follows a git checkout type of model for workflows. All assigned users will see the assignment upon logging in, however when the any one user checks-out, s/he owns the element (control, evidence, checklist etc.) and will disappear from the workqueue of other users.

When a plan is executed, it is called a Plan Instance or a Plan Run. Each Plan Run is a unique copy of the Plan for the selected configuration with Evidences, Checklists, Notes etc.

```Plan + Configuration = Plan Instance```

## Reporting

ComplianceCow allows a flexible reporting mechanism. Reporting in ComplianceCow is organized along the following:

+ Category
  + Dashboard
    + Report
      + Data
        + JSON
        + CSV
        + Parquet
      + Object
        + Chart
        + html
        + pdf

Report is the atomic unit of work that can either return data or a visual object. The data can be specified in multiple formats. A Dashboard is a collection of one or more reports. Each Dashboard is categorized under Category (needless repetition!!) and the categories are nested inside Plans. The Dashboards and the Reports can be for a specific Plan Instance or across multiple Plan Instances or even can span over multiple Plans.

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

