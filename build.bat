dmd -L/subsystem:windows "main.d" "run_dlg.d"
mt.exe -manifest "main.manifest" -outputresource:"main.exe";#1
