; AutoHotkey v2 Script - Ryzen Optimizer SOCD Cleaner

; Set icon and tray tip
I_Icon := A_ScriptDir . "\resources\icon.ico"
if FileExist(I_Icon) {
    A_IconTip := "Ryzen Optimizer | SOCD Cleaner"
    TraySetIcon(I_Icon)
}

; Directives
#Requires AutoHotkey v2.0
#SingleInstance Force
#UseHook true
#Hotstring EndChars `t

; Global variables
lastHorizontal := ""
lastVertical := ""

; Horizontal SOCD (A and D keys)
~a:: {
    global lastHorizontal
    lastHorizontal := "a"
    if GetKeyState("d", "P")
        SendInput("{d up}")
}

~d:: {
    global lastHorizontal
    lastHorizontal := "d"
    if GetKeyState("a", "P")
        SendInput("{a up}")
}

~a up:: {
    global lastHorizontal
    if (lastHorizontal = "a") {
        if GetKeyState("d", "P") {
            SendInput("{d down}")
            lastHorizontal := "d"
        } else {
            lastHorizontal := ""
        }
    }
}

~d up:: {
    global lastHorizontal
    if (lastHorizontal = "d") {
        if GetKeyState("a", "P") {
            SendInput("{a down}")
            lastHorizontal := "a"
        } else {
            lastHorizontal := ""
        }
    }
}

; Vertical SOCD (W and S keys)
~w:: {
    global lastVertical
    lastVertical := "w"
    if GetKeyState("s", "P")
        SendInput("{s up}")
}

~s:: {
    global lastVertical
    lastVertical := "s"
    if GetKeyState("w", "P")
        SendInput("{w up}")
}

~w up:: {
    global lastVertical
    if (lastVertical = "w") {
        if GetKeyState("s", "P") {
            SendInput("{s down}")
            lastVertical := "s"
        } else {
            lastVertical := ""
        }
    }
}

~s up:: {
    global lastVertical
    if (lastVertical = "s") {
        if GetKeyState("w", "P") {
            SendInput("{w down}")
            lastVertical := "w"
        } else {
            lastVertical := ""
        }
    }
}

; SOCD with Shift modifier
~+a:: {
    global lastHorizontal
    lastHorizontal := "a"
    if GetKeyState("d", "P")
        SendInput("{d up}")
}

~+d:: {
    global lastHorizontal
    lastHorizontal := "d"
    if GetKeyState("a", "P")
        SendInput("{a up}")
}

~+a up:: {
    global lastHorizontal
    if (lastHorizontal = "a") {
        if GetKeyState("d", "P") {
            SendInput("{d down}")
            lastHorizontal := "d"
        } else {
            lastHorizontal := ""
        }
    }
}

~+d up:: {
    global lastHorizontal
    if (lastHorizontal = "d") {
        if GetKeyState("a", "P") {
            SendInput("{a down}")
            lastHorizontal := "a"
        } else {
            lastHorizontal := ""
        }
    }
}

~+w:: {
    global lastVertical
    lastVertical := "w"
    if GetKeyState("s", "P")
        SendInput("{s up}")
}

~+s:: {
    global lastVertical
    lastVertical := "s"
    if GetKeyState("w", "P")
        SendInput("{w up}")
}

~+w up:: {
    global lastVertical
    if (lastVertical = "w") {
        if GetKeyState("s", "P") {
            SendInput("{s down}")
            lastVertical := "s"
        } else {
            lastVertical := ""
        }
    }
}

~+s up:: {
    global lastVertical
    if (lastVertical = "s") {
        if GetKeyState("w", "P") {
            SendInput("{w down}")
            lastVertical := "w"
        } else {
            lastVertical := ""
        }
    }
}

; SOCD with Ctrl modifier
~^a:: {
    global lastHorizontal
    lastHorizontal := "a"
    if GetKeyState("d", "P")
        SendInput("{d up}")
}

~^d:: {
    global lastHorizontal
    lastHorizontal := "d"
    if GetKeyState("a", "P")
        SendInput("{a up}")
}

~^a up:: {
    global lastHorizontal
    if (lastHorizontal = "a") {
        if GetKeyState("d", "P") {
            SendInput("{d down}")
            lastHorizontal := "d"
        } else {
            lastHorizontal := ""
        }
    }
}

~^d up:: {
    global lastHorizontal
    if (lastHorizontal = "d") {
        if GetKeyState("a", "P") {
            SendInput("{a down}")
            lastHorizontal := "a"
        } else {
            lastHorizontal := ""
        }
    }
}

~^w:: {
    global lastVertical
    lastVertical := "w"
    if GetKeyState("s", "P")
        SendInput("{s up}")
}

~^s:: {
    global lastVertical
    lastVertical := "s"
    if GetKeyState("w", "P")
        SendInput("{w up}")
}

~^w up:: {
    global lastVertical
    if (lastVertical = "w") {
        if GetKeyState("s", "P") {
            SendInput("{s down}")
            lastVertical := "s"
        } else {
            lastVertical := ""
        }
    }
}

~^s up:: {
    global lastVertical
    if (lastVertical = "s") {
        if GetKeyState("w", "P") {
            SendInput("{w down}")
            lastVertical := "w"
        } else {
            lastVertical := ""
        }
    }
}

; ! BSDK