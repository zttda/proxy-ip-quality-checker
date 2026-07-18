param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\assets')
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$pngPath = Join-Path $OutputDirectory 'app-icon.png'
$icoPath = Join-Path $OutputDirectory 'app-icon.ico'
$size = 256
$bitmap = [System.Drawing.Bitmap]::new($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$graphics.Clear([System.Drawing.Color]::Transparent)

$path = [System.Drawing.Drawing2D.GraphicsPath]::new()
$radius = 48
$diameter = $radius * 2
$bounds = [System.Drawing.Rectangle]::new(8, 8, 240, 240)
$path.AddArc($bounds.Left, $bounds.Top, $diameter, $diameter, 180, 90)
$path.AddArc($bounds.Right - $diameter, $bounds.Top, $diameter, $diameter, 270, 90)
$path.AddArc($bounds.Right - $diameter, $bounds.Bottom - $diameter, $diameter, $diameter, 0, 90)
$path.AddArc($bounds.Left, $bounds.Bottom - $diameter, $diameter, $diameter, 90, 90)
$path.CloseFigure()

$background = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 23, 33, 43))
$graphics.FillPath($background, $path)

$signalPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 38, 194, 129), 16)
$signalPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$signalPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$graphics.DrawArc($signalPen, 48, 48, 160, 160, 35, 285)

$routePen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 75, 150, 220), 9)
$routePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$routePen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$graphics.DrawLine($routePen, 79, 172, 126, 128)
$graphics.DrawLine($routePen, 126, 128, 180, 82)

$nodeBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 245, 248, 250))
$accentBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 255, 185, 60))
$graphics.FillEllipse($nodeBrush, 65, 158, 28, 28)
$graphics.FillEllipse($nodeBrush, 112, 114, 28, 28)
$graphics.FillEllipse($accentBrush, 166, 68, 30, 30)

$bitmap.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
$pngStream = [System.IO.MemoryStream]::new()
$bitmap.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
$pngBytes = $pngStream.ToArray()

$fileStream = [System.IO.File]::Open($icoPath, [System.IO.FileMode]::Create)
$writer = [System.IO.BinaryWriter]::new($fileStream)
$writer.Write([uint16]0)
$writer.Write([uint16]1)
$writer.Write([uint16]1)
$writer.Write([byte]0)
$writer.Write([byte]0)
$writer.Write([byte]0)
$writer.Write([byte]0)
$writer.Write([uint16]1)
$writer.Write([uint16]32)
$writer.Write([uint32]$pngBytes.Length)
$writer.Write([uint32]22)
$writer.Write($pngBytes)

$writer.Dispose()
$fileStream.Dispose()
$pngStream.Dispose()
$accentBrush.Dispose()
$nodeBrush.Dispose()
$routePen.Dispose()
$signalPen.Dispose()
$background.Dispose()
$path.Dispose()
$graphics.Dispose()
$bitmap.Dispose()

Write-Output $icoPath
