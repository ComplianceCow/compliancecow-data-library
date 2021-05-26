# ComplianceCow Data Library
![N|Solid](https://partner.compliancecow.live/assets/images/cow/cowlogo2.png)
You can use this library for consume data from compliancecow directly. After that you can play around your data.

# Things to remember!

  - You can create the client object by the following.
    ```sh
    from compliancecow.models import cowlib
    cowlib.Client(auth_token = '')
    ```
  - auth_token - token which is created by the user login
  - After that you can access the data by the given methods.
  - Every method(which is in client object) in this library always return 2 objects. The 1st will be expected object and the 2nd one'll be error.
  - Each method will return objects. If you need dictionary, there's a implementation for that in <<to_dict()>> in every object(which is standard nowadays).
  - Samples for each methods has been given in the notebooks folder.

### Installation

ComplianceCow requires [Python](https://www.python.org/) v3.7+ to run.

Install the dependencies and devDependencies and start the server.

```sh
$ pip install "library-filepath"
```
# Things can do!

### Meta Data
1.  You can fetch the available plans. example,
    ```sh
    plans, errors = client.get_plans()
    ```
2.  With the plan object, you can fetch the plan instances
3.  You can fetch the available configurations 

### Evidence Data
From the plan instance, you can fetch the evidence data. With the following sample, you may know this better.
1.  There's a method to filter the controls which has evidence data.(Please refer documentation to know better about the params)
    ```sh
    controls = plan_instance.get_plan_instance_controls(having_evidences=True)
    ```
2.  Now you need to find the specific evidence from controls and pass it to the following method.
    ```sh
    data, errors = client.get_evidence_data(evidence=evidence)
    ```
    consider evidence is a valid evidence object. It'll return data as pandas DataFrame
    
### Report
1.  You can also fetch the report data from compliancecow.
2.  If you know the specific report name, you can consume the data by following method.
    ```sh
    report_data, errors = client.get_report_data(report_name=report_name)
    ```
3.  By default we'll return data as JSON. If you need other formats, you can choose from the options.(Please refer the docs)
4.  If you need pandas DataFrame from the ReportData object, you can achieve it by following.
    ```sh
    df , errors = utils.convert_data_to_df(report_data)
    ```
    note : only supported for the formats - JSON and PARQUET
    
##### Note : Other available methods has been given in samples. Apart from that you can refer the docs.
    
