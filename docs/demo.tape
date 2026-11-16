# Terminal recording for the README. Regenerate with: make demo-gif
# Needs vhs (brew install vhs) and a sec-audit binary built by make build.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 1040
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set CursorBlink false

Hide
Type "export PATH=$PWD:$PATH PS1='$ ' && cd $(mktemp -d) && clear"
Enter
Sleep 300ms
Show

Type "sec-audit demo --dir demo"
Sleep 400ms
Enter
Sleep 7s

Type "clear && sec-audit status --output-dir demo/run"
Sleep 300ms
Enter
Sleep 3s

Type "clear && sed -n '1,/^## Preconditions/p' demo/run/advisories/GHSA-notes.export.path-traversal.md | fold -s -w 110"
Sleep 300ms
Enter
Sleep 5s
