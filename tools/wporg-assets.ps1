Add-Type -AssemblyName System.Drawing
$out = Join-Path $PSScriptRoot '..\wporg-assets'
New-Item -ItemType Directory -Force $out | Out-Null

function New-G($bmp) {
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'AntiAliasGridFit'; $g.InterpolationMode = 'HighQualityBicubic'
  return $g
}

function Draw-Shield($g, [single]$x, [single]$y, [single]$s) {
  $p = New-Object System.Drawing.Drawing2D.GraphicsPath
  $p.AddLine($x+16*$s, $y+2*$s, $x+28*$s, $y+7*$s)
  $p.AddLine($x+28*$s, $y+7*$s, $x+28*$s, $y+15*$s)
  $p.AddBezier($x+28*$s, $y+15*$s, $x+28*$s, $y+22.5*$s, $x+22.9*$s, $y+28.4*$s, $x+16*$s, $y+30*$s)
  $p.AddBezier($x+16*$s, $y+30*$s, $x+9.1*$s, $y+28.4*$s, $x+4*$s, $y+22.5*$s, $x+4*$s, $y+15*$s)
  $p.AddLine($x+4*$s, $y+15*$s, $x+4*$s, $y+7*$s)
  $p.CloseFigure()
  $rect = New-Object System.Drawing.RectangleF(($x+4*$s), ($y+2*$s), (24*$s), (28*$s))
  $br = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, [System.Drawing.Color]::FromArgb(56,245,160), [System.Drawing.Color]::FromArgb(45,212,255), [single]45)
  $g.FillPath($br, $p)
  $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(4,18,11), [single](2.6*$s))
  $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
  $pts = [System.Drawing.PointF[]]@(
    (New-Object System.Drawing.PointF(($x+11*$s), ($y+16.5*$s))),
    (New-Object System.Drawing.PointF(($x+14.5*$s), ($y+20*$s))),
    (New-Object System.Drawing.PointF(($x+21.5*$s), ($y+12.5*$s)))
  )
  $g.DrawLines($pen, $pts)
}

function Glow($g, $cx, $cy, $r, $a, $cr, $cg, $cb) {
  $gp = New-Object System.Drawing.Drawing2D.GraphicsPath
  $gp.AddEllipse([single]($cx-$r), [single]($cy-$r), [single](2*$r), [single](2*$r))
  $pb = New-Object System.Drawing.Drawing2D.PathGradientBrush($gp)
  $pb.CenterColor = [System.Drawing.Color]::FromArgb($a, $cr, $cg, $cb)
  $pb.SurroundColors = @([System.Drawing.Color]::FromArgb(0, $cr, $cg, $cb))
  $g.FillPath($pb, $gp)
}

# --- Иконки ---
foreach ($size in 128, 256) {
  $bmp = New-Object System.Drawing.Bitmap($size, $size)
  $g = New-G $bmp
  $g.Clear([System.Drawing.Color]::FromArgb(7,11,20))
  Glow $g ($size*0.5) ($size*0.45) ($size*0.6) 60 45 212 255
  $s = $size / 40.0
  Draw-Shield $g ($size*0.5 - 16*$s) ($size*0.5 - 16*$s) $s
  $bmp.Save((Join-Path $out "icon-${size}x${size}.png"), [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
}

# --- Баннеры ---
foreach ($w in 772, 1544) {
  $k = $w / 772.0
  $h = [int](250 * $k)
  $bmp = New-Object System.Drawing.Bitmap($w, $h)
  $g = New-G $bmp
  $g.Clear([System.Drawing.Color]::FromArgb(7,11,20))
  Glow $g (600*$k) (60*$k) (330*$k) 45 45 212 255
  Glow $g (120*$k) (40*$k) (260*$k) 35 56 245 160
  $gridPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(14,255,255,255), [single]1)
  for ($i = 0; $i -lt $w; $i += [int](26*$k)) { $g.DrawLine($gridPen, $i, 0, $i, $h) }
  for ($i = 0; $i -lt $h; $i += [int](26*$k)) { $g.DrawLine($gridPen, 0, $i, $w, $i) }

  Draw-Shield $g (40*$k) (52*$k) (4.4*$k)
  $white = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(231,237,247))
  $green = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(56,245,160))
  $muted = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(150,162,184))
  $fT = New-Object System.Drawing.Font('Segoe UI', [single](54*$k), [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
  $fS = New-Object System.Drawing.Font('Segoe UI', [single](21*$k), [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
  $fB = New-Object System.Drawing.Font('Segoe UI', [single](15*$k), [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
  $g.DrawString('FYZI', $fT, $white, (190*$k), (52*$k))
  $g.DrawString('Guard', $fT, $green, (322*$k), (52*$k))
  $g.DrawString('Hack protection & admin watchdog for WordPress', $fS, $muted, (194*$k), (128*$k))
  $g.DrawString('FREE  ·  TELEGRAM ALERTS  ·  MADE IN RUSSIA', $fB, $green, (196*$k), (170*$k))
  $bmp.Save((Join-Path $out "banner-${w}x${h}.png"), [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
}
'done'
