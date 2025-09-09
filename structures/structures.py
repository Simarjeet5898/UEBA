from dataclasses import dataclass

@dataclass
class STRING_DATE_TIME_FORMAT:
    dd: int     # day
    mm: int     # month
    yyyy: int   # year
    hh: int     # hour (24hr format)
    min: int    # minute
    ss: int     # second


@dataclass
class STRUCT_ABNORMAL_LOGIN_LOGOUT_TIME:
    msg_id: int
    source_id: str
    event_id: int      # INCIDENT_TYPE (validate using config["incident_type"])
    event_type: int    # EVENT_TYPE (validate using config["event_type"])
    event_name: int    # EVENT_NAME (validate using config["event_name"])
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT      
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int   # DEVICE_TYPE (validate using config["device_type"])
    log_text: str
    severity: int       # SEVERITY (validate using config["severity"])
    pid: str
    ppid: str
    tty: str           # BOOL_YES_NO (validate using config["bool_yes_no"])
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT    
    abnrml_login_logout: STRING_DATE_TIME_FORMAT  


@dataclass
class STRUCT_ACK:
    incidentId: str
    action: str
    actionStatus: int   # SUCCESS_FAIL_FLAG (validate with config: access_decision or similar)
    ackTimestamp: STRING_DATE_TIME_FORMAT
    communicationLog: str



@dataclass
class STRUCT_ANOMALOUS_APPLICATION_USAGE:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int   # INCIDENT_TYPE (validate using config)
    event_name: int   # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int   # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int       # SEVERITY (validate using config)
    pid: str
    ppid: str
    tty: str           # BOOL_YES_NO (validate using config)
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT
    anomalous_application_name: str


@dataclass
class STRUCT_ANOMALOUS_CPU_GPU_RAM_CONSP:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int   # INCIDENT_TYPE (validate using config)
    event_name: int   # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int   # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int       # SEVERITY (validate using config)
    pid: str
    ppid: str
    tty: str           # BOOL_YES_NO (validate using config)
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT


@dataclass
class STRUCT_ANOMALOUS_FILE_ACCESS:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int      # INCIDENT_TYPE (validate using config["incident_type"])
    event_name: int      # EVENT_NAME (validate using config["event_name"])
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int      # DEVICE_TYPE (validate using config["device_type"])
    log_text: str
    severity: int         # SEVERITY (validate using config["severity"])
    pid: str
    ppid: str
    tty: str              # BOOL_YES_NO (validate using config["bool_yes_no"])
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT
    file_name: str
    file_path: str


@dataclass
class STRUCT_ANOMALOUS_USER_SESSION:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int   # INCIDENT_TYPE (validate using config)
    event_name: int   # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int   # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int       # SEVERITY (validate using config)
    pid: str
    ppid: str
    tty: str           # BOOL_YES_NO (validate using config)
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT
    session_duration: float


@dataclass
class STRUCT_BEHAVIOURAL_CHANGE_DETECTION:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int   # INCIDENT_TYPE (validate using config)
    event_name: int   # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int   # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int       # SEVERITY (validate using config)
    pid: str
    ppid: str
    tty: str           # BOOL_YES_NO (validate using config)
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT


@dataclass
class STRUCT_BLK_DATA_OP_MONI_DETECTION:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int        # INCIDENT_TYPE (validate using config["incident_type"])
    event_name: int        # EVENT_NAME (validate using config["event_name"])
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int       # DEVICE_TYPE (validate using config["device_type"])
    log_text: str
    severity: int          # SEVERITY (validate using config["severity"])
    pid: str
    ppid: str
    tty: str               # BOOL_YES_NO (validate using config["bool_yes_no"])
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT
    operation_type: int    # OPERATION_TYPE (validate using config["operation_type"])
    operation_size: float


# @dataclass
# class STRUCT_BRUTE_FORCE_ATTACK_DETECTION:
#     msgId: int
#     sourceId: str
#     eventId: str
#     eventType: int    # INCIDENT_TYPE (validate using config)
#     eventName: int    # EVENT_NAME (validate using config)
#     eventReason: str
#     timestamp: STRING_DATE_TIME_FORMAT
#     attackerIpAddress: str
#     attackerUsername: str
#     deviceHostname: str
#     deviceUsername: str
#     deviceMacId: str
#     deviceIpAddress: str
#     deviceType: int   # DEVICE_TYPE (validate using config)
#     logText: str
#     serverity: int    # SEVERITY (validate using config)
#     queryText: str
#     dbName: str
#     dbUser: str
#     queryDuration: float
#     dbAction: int     # DB_ACTION (validate using config)

@dataclass
class STRUCT_COMMAND_EXE_MONI:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int    # INCIDENT_TYPE (validate using config)
    event_name: int    # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int   # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int       # SEVERITY (validate using config)
    pid: str
    ppid: str
    tty: str           # BOOL_YES_NO (validate using config)
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT
    command_text: str
    command_exe_duration: float
    command_repetition: str  # BOOL_YES_NO (validate using config)


@dataclass
class STRUCT_DATA_EXFILTRATION_ATTEMPTS_DETECTION:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int     # INCIDENT_TYPE (validate using config)
    event_name: int     # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int    # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int       # SEVERITY (validate using config)
    port: str
    protocol_used: str
    file_name: str
    file_type: str
    transfer_size: float
    destination_ip_add: str
    destination_domain: str


@dataclass
class STRUCT_DOS_DDOS_DETECTION:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int        # INCIDENT_TYPE (validate using config)
    event_name: int        # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int       # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int          # SEVERITY (validate using config)
    port: str
    protocol_used: str
    bytes_sents_or_received: int


@dataclass
class STRUCT_FILE_SYS_MONI:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int        # INCIDENT_TYPE (validate using config)
    event_name: int        # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int       # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int           # SEVERITY (validate using config)
    pid: str
    ppid: str
    tty: str               # BOOL_YES_NO (validate using config)
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT
    operation_type: int    # OPERATION_TYPE (validate using config)
    file_name: str
    file_path: str
    frequency_count: int   # UINT_16


@dataclass
class STRUCT_SOAR_ACK:
    msgId: int
    incidentId: str
    action: str
    actionStatus: str                   # SUCCESS_FAIL_FLAG (validate using config)
    acknowledgementTimestamp: str
    communicationLog: str


@dataclass
class STRUCT_SOAR_ACTION:
    msg_id: int
    incident_id: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    target_ip: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    action_name: str
    action_attributes: int   # INCIDENT_TYPE (validate using config)


@dataclass
class STRUCT_SSH_BRUTE_FORCE_DETECTION:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int      # INCIDENT_TYPE (validate using config)
    event_name: int      # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int     # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int        # SEVERITY (validate using config)
    port: str
    protocol_used: str
    failed_login_attempts: int
    username_attempted: str
    login_attempt_rate: int


@dataclass
class STRUCT_UEBA_SETTING:
    msgId: int
    sourceId: str
    eventId: str
    eventType: int      # EVENT_TYPE (validate using config)
    eventName: int      # EVENT_NAME (validate using config)
    eventReason: str
    timeStamp: STRING_DATE_TIME_FORMAT
    attackerIpAddress: str
    attackerUsername: str
    deviceHostname: str
    deviceUsername: str
    deviceMacId: str
    deviceIpAddress: str
    devicetype: int     # DEVICE_TYPE (validate using config)
    logText: str
    severity: int       # SEVERITY (validate using config)
    pid: str
    ppid: str
    tty: str            # YES_NO_FLAG (validate using config)
    cputime: float
    sTime: STRING_DATE_TIME_FORMAT
    sessionId: str
    abnoramlLoginTIme: STRING_DATE_TIME_FORMAT
    anomalousApplicationName: str
    commandExecutionDuration: float
    commandRepitition: str   # YES_NO_FLAG (validate using config)
    commandText: str
    dormantDomain: float
    fileName: str
    filePath: str
    frequrencyCount: int
    opreationSize: float
    operationType: int   # OPERATION_TYPE (validate using config)
    priviledgeEscalationAttempt: str   # SUCCESS_FAIL_FLAG (validate using config)
    priviledgeEscalationCommand: str
    sessionDuration: float
    sourceRole: str
    suspiciousIpDetected: str   # YES_NO_FLAG (validate using config)
    targetRole: str
    userRole: str


@dataclass
class STRUCT_UNUSED_ACC_ACTIVITY:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int      # INCIDENT_TYPE (validate using config)
    event_name: int      # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int     # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int         # SEVERITY (validate using config)
    pid: str
    ppid: str
    tty: str             # BOOL_YES_NO (validate using config)
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT
    session_id: str
    session_duration: float
    dormant_duration: float


@dataclass
class STRUCT_PRIVILEGED_USER_MONI:
    msg_id: int
    source_id: str
    event_id: str
    event_type: int      # INCIDENT_TYPE (validate using config)
    event_name: int      # EVENT_NAME (validate using config)
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int     # DEVICE_TYPE (validate using config)
    log_text: str
    severity: int         # SEVERITY (validate using config)
    pid: str
    ppid: str
    tty: str             # BOOL_YES_NO (validate using config)
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT
    user_role: str



@dataclass
class STRUCT_PRIVILEGE_ESCALATION_MONI:
    msg_id: int
    source_id: str
    event_id: int              # INCIDENT_TYPE (validate using config["incident_type"])
    event_type: int            # EVENT_TYPE (validate using config["event_type"])
    event_name: int            # EVENT_NAME (validate using config["event_name"])
    event_reason: str
    timestamp: STRING_DATE_TIME_FORMAT
    attacker_ip_address: str
    attacker_username: str
    device_hostname: str
    device_username: str
    device_mac_id: str
    device_ip_add: str
    device_type: int           # DEVICE_TYPE (validate using config["device_type"])
    log_text: str
    severity: int              # SEVERITY (validate using config["severity"])
    pid: str
    ppid: str
    tty: str                   # BOOL_YES_NO (validate using config["bool_yes_no"])
    cpu_time: float
    start_time: STRING_DATE_TIME_FORMAT
    privilege_escalation_attempt: str   # BOOL_YES_NO (validate using config["bool_yes_no"])
    privilege_escalation_cmd: str
    source_role: str
    target_role: str
