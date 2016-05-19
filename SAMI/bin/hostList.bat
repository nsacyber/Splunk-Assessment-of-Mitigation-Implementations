@ECHO OFF
powershell -Command "& { get-adcomputer -filter 'Enabled -eq \"True\"' -properties Name, lastLogon | select-object Name, lastLogon | format-table -Autosize -Hidetableheaders }"