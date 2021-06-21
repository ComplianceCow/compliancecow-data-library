import os

SecurityContext = "X-Cow-Security-Context"
VersionSplitter = "_"

ComplinaceCowProtocol = os.getenv("COW_SERVER_PROTOCOL", "https")
ComplinaceCowHostName = os.getenv("COW_SERVER_HOST", "dev.compliancecow.live")


Items = "items"
