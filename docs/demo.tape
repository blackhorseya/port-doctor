# Record with: vhs docs/demo.tape   (brew install vhs)
Output docs/demo.gif

Set Shell zsh
Set FontSize 16
Set Width 900
Set Height 560
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms

Hide
Type "python3 -m http.server 8080 >/dev/null 2>&1 &" Enter
Sleep 1s
Type "clear" Enter
Show

Type "port-doctor 8080" Sleep 500ms Enter
Sleep 4s

Hide
Type "kill %1; sleep 1; clear" Enter
Show

Type "port-doctor 8080" Sleep 500ms Enter
Sleep 3s
