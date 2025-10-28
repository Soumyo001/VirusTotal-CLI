import os

class Paths:
    CONFIG_PATH = os.path.expanduser("~/.config/vtcli/config.json")
    BASE_URL = "https://www.virustotal.com/api/v3"
    API_KEY_ENTRY = "api_key"

class Analysis:
    DATA = "data"
    TYPE = "type"
    ID = "id"
    LINKS = "links"
    LINKS_SELF = "self"
    LINKS_ITEM = "item"
    RESULTS = "results"
    FILE_META = "meta"
    FILE_META_INFO = "file_info"
    ATTRIBUTES = "attributes"
    ATTRIBUTES_STATS = "stats"
    ATTRIBUTES_RESULTS = "results"
    ATTRIBUTES_RESULTS_AVNAME = "engine_name"
    ATTRIBUTES_RESULTS_AVMETHOD = "method"
    ATTRIBUTES_RESULTS_AVRESULT = "result"
    ATTRIBUTES_RESULTS_AVDETECT_CATEGORY = "category"

class File_MetaData:
    FILE_META_DATA = ["sha256", "md5", "sha1", "size"]

class Response:
    ERROR = "error"
    ERROR_CODE = "code"
    ERROR_MESSAGE = "message"