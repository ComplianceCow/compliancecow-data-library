import os

SecurityContext = "X-Cow-Security-Context"
VersionSplitter = "_"

ComplinaceCowProtocol = os.getenv(
    "COW_CLI_DATA_CONSUMER_SERVICE_PROTOCOL", "https")
ComplinaceCowHostName = os.getenv(
    "COW_CLI_DATA_CONSUMER_SERVICE_SERVER_HOST", "dev.compliancecow.live")

RuleEngineProtocol = os.getenv(
    "CN_PLATFORM_API_SERVICE_PROTOCOL", "https")
RuleEngineHostName = os.getenv(
    "CN_PLATFORM_API_SERVICE_HOST_NAME", "dev.continube.live")

CLIEnvironment = os.getenv(
    "CLI_ENVIRONMENT", "dev")

RuleEngineURL = "%s://%s" % (RuleEngineProtocol, RuleEngineHostName)

Items = "items"
