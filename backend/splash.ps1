# NetGuard splash - visible while the hidden app starts.
# Shows immediately after the desktop icon is clicked, polls the local app,
# opens the page when it answers, then closes itself. No console anywhere.
# Design: simple logo + loading dots. Nothing else.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# getting the current foreground window's title (the browser shows the
# ACTIVE tab's title in its window title - our realtime-handover signal)
Add-Type -Namespace W -Name U32 -MemberDefinition @'
[DllImport("user32.dll")] public static extern System.IntPtr GetForegroundWindow();
[DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern int GetWindowTextW(System.IntPtr hWnd, System.Text.StringBuilder text, int count);
'@

$root     = Split-Path -Parent $PSScriptRoot          # repo root
$iconPath = Join-Path $root 'backend\assets\app.ico'
$pageUrl  = 'http://127.0.0.1:8000'

$script:attempts    = 0
$script:maxAttempts = 120                             # ~90 s of patience
$script:opened      = $false
$script:openedTicks = 0
$script:browserStarted = $false
$script:ticks       = 0

# --- window icon (best effort; the drawn shield is what you see) ------------- #
try {
    $formIcon = New-Object System.Drawing.Icon($iconPath, 64, 64)
} catch {
    $formIcon = $null
}

# --- simple shield - flat, no glow, no pulse ---------------------------------- #
function Test-PageOnTop {
    try {
        $sb = New-Object System.Text.StringBuilder 512
        [void][W.U32]::GetWindowTextW([W.U32]::GetForegroundWindow(), $sb, 512)
        return ($sb.ToString() -clike '*NetGuard*')
    } catch {
        return $false
    }
}

function Draw-Shield {
    param($g, $cx, $cy)

    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

    $halfW = 30
    $topY  = $cy - 33
    $botY  = $cy + 31

    # shield outline (Concept 2 - N + Shield)
    $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
    $shield.AddArc(($cx - $halfW), $topY, $halfW, $halfW, 180, 90)
    $shield.AddArc(($cx + $halfW - $halfW), $topY, $halfW, $halfW, 270, 90)
    $shield.AddLine(($cx + $halfW), ($topY + 24), ($cx + $halfW), ($topY + 36))
    $shield.AddBezier(($cx + $halfW), ($topY + 36), ($cx + $halfW), ($topY + 50), ($cx + 15), ($botY - 6), $cx, $botY)
    $shield.AddBezier($cx, $botY, ($cx - 15), ($botY - 6), ($cx - $halfW), ($topY + 50), ($cx - $halfW), ($topY + 36))
    $shield.AddLine(($cx - $halfW), ($topY + 36), ($cx - $halfW), ($topY + 24))
    $shield.CloseFigure()

    $outlinePen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(229, 231, 235)), 2.2
    $g.DrawPath($outlinePen, $shield)
    $outlinePen.Dispose()

    # N strokes
    $leftX  = $cx - 16
    $rightX = $cx + 16
    $topN   = $topY + 12
    $botN   = $botY - 12

    $strokePen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(229, 231, 235)), 3.0
    $strokePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Square
    $strokePen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Square
    $g.DrawLine($strokePen, $leftX,  $topN, $leftX,  $botN)
    $g.DrawLine($strokePen, $rightX, $topN, $rightX, $botN)
    $strokePen.Dispose()

    # diagonal (cyan accent)
    $diagPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(34, 211, 238)), 3.0
    $diagPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Square
    $diagPen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Square
    $g.DrawLine($diagPen, $leftX, $topN, $rightX, $botN)
    $diagPen.Dispose()
}


# --- dark rounded window ------------------------------------------------------ #
$form = New-Object System.Windows.Forms.Form
$form.FormBorderStyle  = 'None'
$form.StartPosition    = 'CenterScreen'
$form.Size             = New-Object System.Drawing.Size(300, 170)
$form.BackColor        = [System.Drawing.Color]::FromArgb(10, 10, 11)
$form.ForeColor        = [System.Drawing.Color]::FromArgb(229, 231, 235)
$form.TopMost          = $true
$form.ShowInTaskbar    = $true
$form.Text             = 'NetGuard'
$form.DoubleBuffered   = $true
$form.Opacity          = 0            # fade in - prevents any white first-paint flash
if ($formIcon) { $form.Icon = $formIcon }

# rounded corners
$radius = 22
$form.Region = {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $p.AddArc(0, 0, $radius, $radius, 180, 90)
    $p.AddArc($form.ClientSize.Width - $radius, 0, $radius, $radius, 270, 90)
    $p.AddArc($form.ClientSize.Width - $radius, $form.ClientSize.Height - $radius, $radius, $radius, 0, 90)
    $p.AddArc(0, $form.ClientSize.Height - $radius, $radius, $radius, 90, 90)
    $p.CloseFigure()
    return $p
}.Invoke()

# --- quiet close (X) ------------------------------------------------------------ #
$closeBtn = New-Object System.Windows.Forms.Label
$closeBtn.Text      = [char]0xD7
$closeBtn.Font      = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$closeBtn.ForeColor = [System.Drawing.Color]::FromArgb(85, 88, 94)
$closeBtn.AutoSize  = $false
$closeBtn.Size      = New-Object System.Drawing.Size(26, 24)
$closeBtn.Location  = New-Object System.Drawing.Point($form.ClientSize.Width - 30, 6)
$closeBtn.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$closeBtn.Cursor    = [System.Windows.Forms.Cursors]::Hand
$closeBtn.Add_Click({ $form.Close() })
$form.Controls.Add($closeBtn)

# --- loading dots ---------------------------------------------------------------- #
$dots = New-Object System.Windows.Forms.Label
$dots.Text      = 'Loading'
$dots.Font      = New-Object System.Drawing.Font('Segoe UI', 10)
$dots.ForeColor = [System.Drawing.Color]::FromArgb(130, 136, 142)
$dots.AutoSize  = $false
$dots.Size      = New-Object System.Drawing.Size(300, 24)
$dots.Location  = New-Object System.Drawing.Point(0, 112)
$dots.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$form.Controls.Add($dots)

$form.Add_Paint({
    param($sender, $e)
    Draw-Shield $e.Graphics ($form.ClientSize.Width / 2) 62
})

# --- full-screen takeover cover (shown at "opening the page") ---------------- #
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$cover = New-Object System.Windows.Forms.Form
$cover.FormBorderStyle = 'None'
$cover.StartPosition   = 'Manual'
$cover.Bounds          = New-Object System.Drawing.Rectangle 0, 0, $screen.Width, $screen.Height
$cover.BackColor       = [System.Drawing.Color]::FromArgb(10, 10, 11)
$cover.TopMost         = $true
$cover.ShowInTaskbar   = $false
$cover.DoubleBuffered  = $true
$cover.Opacity         = 0            # fade in like the splash - no white first-paint flash
$coverDots = New-Object System.Windows.Forms.Label
$coverDots.Text      = 'Loading'
$coverDots.Font      = New-Object System.Drawing.Font('Segoe UI', 10)
$coverDots.ForeColor = [System.Drawing.Color]::FromArgb(130, 136, 142)
$coverDots.AutoSize  = $false
$coverDots.Size      = New-Object System.Drawing.Size(400, 26)
$coverDots.Location  = New-Object System.Drawing.Point([int](($screen.Width - 400) / 2), [int]($screen.Height / 2) + 72)
$coverDots.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$cover.Controls.Add($coverDots)
$cover.Add_Paint({
    param($sender, $e)
    Draw-Shield $e.Graphics ($screen.Width / 2) ([int]($screen.Height / 2) - 14)
})

# closing the splash always takes the cover with it
$form.Add_FormClosed({
    if ($cover.Visible) { $cover.Close() }
})

# --- timers ------------------------------------------------------------------------ #
$uiTimer = New-Object System.Windows.Forms.Timer
$uiTimer.Interval = 45
$uiTimer.Add_Tick({
    $script:ticks++
    # smooth fade-in from invisible (kills any white flash at creation)
    if ($form.Opacity -lt 1) {
        $form.Opacity = [Math]::Min(1.0, $form.Opacity + 0.09)
    }
    # breathing dots
    $n = [int](($script:ticks / 8) % 4)
    $dots.Text      = 'Loading' + ('.' * $n)
    $coverDots.Text = 'Loading' + ('.' * $n)

    if ($script:opened) {
        $script:openedTicks++

        # stage 1: fade the cover to full opacity
        if ($cover.Opacity -lt 1) {
            $cover.Opacity = [Math]::Min(1.0, $cover.Opacity + 0.14)
            return
        }
        # stage 2: cover is solid dark - NOW start the browser
        if (-not $script:browserStarted) {
            $script:browserStarted = $true
            Start-Process $pageUrl
            return
        }

        # stage 3: every ~90 ms, is the page actually in front on screen?
        # (the browser's window title IS the active tab's title, and we only
        # hand over once our tab is the one you can actually see)
        $script:openedTicks++
        $pageOnTop = Test-PageOnTop
        # give painting a moment even after instant detection, bail at 4.5 s
        if (($pageOnTop -and $script:openedTicks -ge 16) -or $script:openedTicks -ge 100) {
            $cover.Close()
            $cover.Dispose()
            $uiTimer.Stop()
            $form.Close()
        }
    }
})
$uiTimer.Start()

$pollTimer = New-Object System.Windows.Forms.Timer
$pollTimer.Interval = 700
$pollTimer.Add_Tick({
    $script:attempts++
    if ($script:opened) { return }

    $up = $false
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async  = $client.BeginConnect('127.0.0.1', 8000, $null, $null)
        $ok = $async.AsyncWaitHandle.WaitOne(400)
        if ($ok -and $client.Connected) { $up = $true }
        $client.Close()
    } catch { $up = $false }

    if ($up) {
        $script:opened        = $true
        $script:openedTicks   = 0
        $script:browserStarted = $false
        # the cover fades itself in; the uiTimer starts the browser only once
        # it is fully opaque, so the browser's white paint is never visible
        $cover.Show()
        $cover.BringToFront()
        $cover.Refresh()
        return
    }
})
$pollTimer.Start()

[System.Windows.Forms.Application]::Run($form)
