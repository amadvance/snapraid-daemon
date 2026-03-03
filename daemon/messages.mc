; // daemon.mc

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

LanguageNames=(English=0x409:MSG00401)

; // --- MESSAGE DEFINITIONS ---

MessageId=100
Severity=Informational
SymbolicName=MSG_INFO
Language=English
INFO: %1
.

MessageId=101
Severity=Warning
SymbolicName=MSG_WARN
Language=English
WARNING: %1
.

MessageId=102
Severity=Error
SymbolicName=MSG_ERROR
Language=English
ERROR: %1
.
