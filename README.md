# ComplianceCow Data Library

You can use this library for consume data from compliancecow directly by making server calls instead of webcall. After that you can play around your data.

# Things to remember!

  - You can either give a credential file or pass it as dictionary while creating the client object.
    ex: client.Client(filepath) or client.Client(credentialdict={})
  - After that you can access the data by the given methods.

### Installation

ComplianceCow requires [Python](https://www.python.org/) v3.7+ to run.

Install the dependencies and devDependencies and start the server.

```sh
$ pip install "library-filepath"
```