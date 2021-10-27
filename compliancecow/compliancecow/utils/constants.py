import os

SecurityContext = "X-Cow-Security-Context"
VersionSplitter = "_"

ComplinaceCowProtocol = os.getenv(
    "COW_CLI_DATA_CONSUMER_SERVICE_PROTOCOL", "https")
ComplinaceCowHostName = os.getenv(
    "COW_CLI_DATA_CONSUMER_SERVICE_SERVER_HOST", "dev.compliancecow.live")


Items = "items"
