@echo off

cl /nologo /W3 /MT /GS- /Od /Zi test.c /link /entry:main /out:test.exe

del *.obj