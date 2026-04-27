rem set "BINCOMPARE=-ldflags=-s -w"
rem set "BINCOMPARE=@buildcompare.args" hallucinated by Gemini
rem set "BINCOMPARE=-trimpath -ldflags='-buildid= -s -w'"
set BINCOMPARE=-trimpath "-ldflags=-s -w -buildid="
call buildwrace.bat
pause