import re

line = 'type=EXECVE msg=audit(1721213470.999:26553900): argc=2 a0="/bin/echo" a1="testing123"'

m = re.search(
    r'audit\((\d+\.\d+):(\d+)\).*?a0="([^"]+)"(?: a1="([^"]+)")?(?: a2="([^"]+)")?(?: a3="([^"]+)")?',
    line
)

if m:
    ts_epoch, record_id, a0, a1, a2, a3 = m.groups()
    print("ts_epoch:", ts_epoch)
    print("record_id:", record_id)
    print("a0:", a0)
    print("a1:", a1)
    print("a2:", a2)
    print("a3:", a3)
else:
    print("No match")
