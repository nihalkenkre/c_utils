@echo off

cl /nologo /W3 /MT /GS- /Od test.c /link /entry:main /machine:x64 /out:test.exe

del *.obj