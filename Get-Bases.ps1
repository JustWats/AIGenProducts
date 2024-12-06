[System.STAThread()]param()
# https://chatgpt.com/share/67533050-2a4c-800f-8f16-15a2ae5e7a60
Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase

# On-demand data retrieval with arrays, limiting large sets
$dataScripts = @{
    "OS" = {
        @(Get-CimInstance -ClassName Win32_OperatingSystem)
    }
    "ComputerSystem" = {
        @(Get-CimInstance -ClassName Win32_ComputerSystem)
    }
    "BIOS" = {
        @(Get-CimInstance -ClassName Win32_BIOS)
    }
    "CPU" = {
        @(Get-CimInstance -ClassName Win32_Processor)
    }
    "Memory" = {
        @(Get-CimInstance -ClassName Win32_PhysicalMemory)
    }
    "DiskDrives" = {
        @(Get-CimInstance -ClassName Win32_DiskDrive)
    }
    "LogicalDisks" = {
        @(Get-CimInstance -ClassName Win32_LogicalDisk)
    }
    "Volumes" = {
        @(Get-CimInstance -ClassName Win32_Volume)
    }
    "NetworkAdapters" = {
        @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object IPEnabled)
    }
    "Software" = {
        @(Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
          Select-Object DisplayName,DisplayVersion,Publisher,InstallDate)
    }
    "Hotfixes" = {
        @(Get-HotFix)
    }
    "Services" = {
        @(Get-Service)
    }
    # Limit processes for speed
    "Processes" = {
        @(Get-Process | Select-Object -First 50)
    }
    "StartupCommands" = {
        @(Get-CimInstance -ClassName Win32_StartupCommand)
    }
    "FirewallRules" = {
        @(Get-NetFirewallRule | Select-Object DisplayName,Direction,Action,Enabled,Profile,Service)
    }
    "EnvVars" = {
        @(Get-ChildItem env: | Select-Object Name,Value)
    }
}

$dataCache = [System.Collections.Generic.Dictionary[string,object]]::new()

function Add-SearchString {
    param([object[]]$data)
    foreach ($item in $data) {
        $values = $item.PSObject.Properties | ForEach-Object {
            if ($_.Value) { $_.Value.ToString() } else { "" }
        }
        $searchString = ($values -join " ").ToLower()
        $item | Add-Member -MemberType NoteProperty -Name _SearchString -Value $searchString -Force
    }
}

$window = New-Object System.Windows.Window
$window.Title = "⚙️ System Baseline Tool"
$window.WindowState = 'Maximized'
$window.WindowStartupLocation = 'CenterScreen'

$lightBackground = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(240,240,240)))
$darkWindowBg = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(30,30,30)))

$banner = New-Object System.Windows.Controls.Border
$banner.Height = 80
$banner.Margin = "0,0,0,5"

$bannerPanel = New-Object System.Windows.Controls.StackPanel
$bannerPanel.Orientation = 'Vertical'
$bannerPanel.VerticalAlignment = 'Center'
$bannerPanel.Margin = "10,0,0,0"

$title = New-Object System.Windows.Controls.TextBlock
$title.Text = "System Baseline Tool"
$title.FontSize = 28
$title.FontWeight = [System.Windows.FontWeights]::Bold
$title.Foreground = 'White'

$subtitle = New-Object System.Windows.Controls.TextBlock
$subtitle.Text = "Select a dataset and filter results easily."
$subtitle.FontSize = 15
$subtitle.Opacity = 0.9
$subtitle.Foreground = 'White'

$bannerPanel.Children.Add($title)
$bannerPanel.Children.Add($subtitle)
$banner.Child = $bannerPanel

$dockPanel = New-Object System.Windows.Controls.DockPanel
[System.Windows.Controls.DockPanel]::SetDock($banner, [System.Windows.Controls.Dock]::Top)
$dockPanel.Children.Add($banner)

$mainGrid = New-Object System.Windows.Controls.Grid
[System.Windows.Controls.DockPanel]::SetDock($mainGrid, [System.Windows.Controls.Dock]::Bottom)
$dockPanel.Children.Add($mainGrid)

$mainGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
$gridRowDef2 = New-Object System.Windows.Controls.RowDefinition
$gridRowDef2.Height = '*'
$mainGrid.RowDefinitions.Add($gridRowDef2)

$selectBorder = New-Object System.Windows.Controls.Border
$selectBorder.BorderBrush = 'LightGray'
$selectBorder.BorderThickness = 1
$selectBorder.CornerRadius = 5
$selectBorder.Margin = "10"
$selectBorder.Padding = "10"

$selectPanel = New-Object System.Windows.Controls.StackPanel
$selectPanel.Orientation = 'Horizontal'
$selectPanel.VerticalAlignment = 'Center'

$datasetLabel = New-Object System.Windows.Controls.TextBlock
$datasetLabel.Text = "⚙️ Choose Data Set:"
$datasetLabel.FontWeight = [System.Windows.FontWeights]::Bold
$datasetLabel.FontSize = 14
$datasetLabel.VerticalAlignment = 'Center'
$datasetLabel.Margin = "0,0,10,0"
$datasetLabel.Foreground = 'Black'

$combo = New-Object System.Windows.Controls.ComboBox
$combo.Width = 200
$combo.FontSize = 14
$combo.ItemsSource = $dataScripts.Keys
$combo.SelectedIndex = -1
$combo.ToolTip = "Select which data set you want to view."
$combo.Margin = "0,0,20,0"
$combo.Foreground = 'Black'

$filterLabel = New-Object System.Windows.Controls.TextBlock
$filterLabel.Text = "🔍 Filter:"
$filterLabel.VerticalAlignment = 'Center'
$filterLabel.FontSize = 14
$filterLabel.Margin = "0,0,10,0"
$filterLabel.Foreground = 'Black'

$filterBox = New-Object System.Windows.Controls.TextBox
$filterBox.Width = 200
$filterBox.FontSize = 14
$filterBox.ToolTip = "Type here to filter results by any matching text."
$filterBox.Margin = "0,0,10,0"
$filterBox.Foreground = 'Black'

$clearFilter = New-Object System.Windows.Controls.Button
$clearFilter.Content = "Clear"
$clearFilter.FontSize = 14
$clearFilter.ToolTip = "Clear the current filter."
$clearFilter.Margin = "0,0,10,0"
$clearFilter.Foreground = 'Black'

$toggleDarkModeBtn = New-Object System.Windows.Controls.Button
$toggleDarkModeBtn.Content = "Dark Mode"
$toggleDarkModeBtn.FontSize = 14
$toggleDarkModeBtn.ToolTip = "Toggle Dark/Light Mode"
$toggleDarkModeBtn.Foreground = 'Black'

$selectPanel.Children.Add($datasetLabel)
$selectPanel.Children.Add($combo)
$selectPanel.Children.Add($filterLabel)
$selectPanel.Children.Add($filterBox)
$selectPanel.Children.Add($clearFilter)
$selectPanel.Children.Add($toggleDarkModeBtn)

$selectBorder.Child = $selectPanel
[System.Windows.Controls.Grid]::SetRow($selectBorder, 0)
$mainGrid.Children.Add($selectBorder)

$dataGridBorder = New-Object System.Windows.Controls.Border
$dataGridBorder.BorderBrush = 'Gray'
$dataGridBorder.BorderThickness = '1'
$dataGridBorder.CornerRadius = "5"
$dataGridBorder.Padding = "5"
$dataGridBorder.Margin = "10"

$dataGrid = New-Object System.Windows.Controls.DataGrid
$dataGrid.AutoGenerateColumns = $true
$dataGrid.IsReadOnly = $true
$dataGrid.EnableRowVirtualization = $true
$dataGrid.EnableColumnVirtualization = $true
$dataGrid.VerticalScrollBarVisibility = 'Auto'
$dataGrid.HorizontalScrollBarVisibility = 'Auto'
$dataGrid.GridLinesVisibility = 'Horizontal'
$dataGrid.HeadersVisibility = 'Column'
$dataGrid.ColumnHeaderHeight = 30
$dataGrid.Foreground = 'Black'

$dataGridBorder.Child = $dataGrid
[System.Windows.Controls.Grid]::SetRow($dataGridBorder, 1)
$mainGrid.Children.Add($dataGridBorder)

$global:isDarkMode = $false

# Styles for DataGrid headers
$bgProperty = [System.Windows.Controls.Control]::BackgroundProperty
$fgProperty = [System.Windows.Controls.Control]::ForegroundProperty
$headerStyle = New-Object System.Windows.Style([System.Windows.Controls.Primitives.DataGridColumnHeader])

# Create a style for ComboBoxItem to ensure readable dropdowns
$comboItemStyle = New-Object System.Windows.Style([System.Windows.Controls.ComboBoxItem])

function Load-Data {
    param([string]$key)
    if (!$dataCache.ContainsKey($key)) {
        $data = & $dataScripts[$key]
        if ($data -isnot [System.Collections.IEnumerable]) {
            $data = @($data)
        }
        $dataCache[$key] = $data
    }
    return $dataCache[$key]
}

function Apply-Filter {
    if ($combo.SelectedIndex -lt 0) {
        $dataGrid.ItemsSource = $null
        return
    }
    $selectedKey = $combo.SelectedItem
    $data = Load-Data $selectedKey
    $filter = $filterBox.Text

    if ([string]::IsNullOrWhiteSpace($filter)) {
        $dataGrid.ItemsSource = $data
    } else {
        if ($data -and $data.Count -gt 0 -and $data[0].PSObject.Properties.Name -notcontains '_SearchString') {
            Add-SearchString $data
        }
        $search = $filter.ToLower()
        
        # Using -like for substring search
        $filtered = $data | Where-Object {
            $_._SearchString -like "*$search*"
        }
        $dataGrid.ItemsSource = $filtered
    }
}

function Apply-Theme {
    param([bool]$darkMode)
    $headerStyle.Setters.Clear()
    $comboItemStyle.Setters.Clear()

    if ($darkMode) {
        # Dark Mode
        $window.Background = $darkWindowBg
        $banner.Background = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(0,0,0)))
        $mainGrid.Background = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(30,30,30)))
        $selectBorder.Background = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(50,50,50)))

        $combo.Background = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(60,60,60)))
        $filterBox.Background = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(60,60,60)))
        $clearFilter.Background = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(60,60,60)))
        $toggleDarkModeBtn.Background = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(60,60,60)))

        # ComboBoxItem style in dark mode
        $comboItemStyle.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Control]::BackgroundProperty,(New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(60,60,60))))))
        $comboItemStyle.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Control]::ForegroundProperty,(New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Colors]::White)))))

        $combo.ItemContainerStyle = $comboItemStyle

        $title.Foreground = 'White'
        $subtitle.Foreground = 'White'
        $datasetLabel.Foreground = 'White'
        $filterLabel.Foreground = 'White'
        $combo.Foreground = 'White'
        $filterBox.Foreground = 'White'
        $clearFilter.Foreground = 'White'
        $toggleDarkModeBtn.Foreground = 'White'
        $dataGrid.Foreground = 'White'

        $dataGrid.Background = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(35,35,35)))
        $dataGrid.RowBackground = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(35,35,35)))
        $dataGrid.AlternatingRowBackground = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(45,45,45)))

        $headerStyle.Setters.Add((New-Object System.Windows.Setter($bgProperty,(New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(60,60,60))))))
        $headerStyle.Setters.Add((New-Object System.Windows.Setter($fgProperty,(New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Colors]::White)))))

        $dataGrid.ColumnHeaderStyle = $headerStyle

        $toggleDarkModeBtn.Content = "Light Mode"
    }
    else {
        # Light Mode with animated banner
        $lg = New-Object System.Windows.Media.LinearGradientBrush
        $lg.StartPoint = "0,0"
        $lg.EndPoint = "1,0"

        # Use -ArgumentList to properly specify parameters for GradientStop
        $stop1 = New-Object System.Windows.Media.GradientStop -ArgumentList ([System.Windows.Media.Colors]::LightSteelBlue), 0.0
        $stop2 = New-Object System.Windows.Media.GradientStop -ArgumentList ([System.Windows.Media.Colors]::SteelBlue), 1.0

        $lg.GradientStops.Add($stop1)
        $lg.GradientStops.Add($stop2)

        $window.Background = $lightBackground
        $banner.Background = $lg

        $bg = New-Object System.Windows.Media.LinearGradientBrush([System.Windows.Media.Colors]::WhiteSmoke, [System.Windows.Media.Colors]::White, 90)
        $bg.SpreadMethod = [System.Windows.Media.GradientSpreadMethod]::Pad
        $mainGrid.Background = $bg

        $selectBorder.Background = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(250,250,250)))

        $title.Foreground = 'White'
        $subtitle.Foreground = 'White'
        $datasetLabel.Foreground = 'Black'
        $filterLabel.Foreground = 'Black'
        $combo.Foreground = 'Black'
        $combo.Background = 'White'
        $filterBox.Foreground = 'Black'
        $filterBox.Background = 'White'
        $clearFilter.Foreground = 'Black'
        $clearFilter.Background = 'White'
        $toggleDarkModeBtn.Foreground = 'Black'
        $toggleDarkModeBtn.Background = 'White'

        $comboItemStyle.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Control]::BackgroundProperty,(New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Colors]::White)))))
        $comboItemStyle.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Control]::ForegroundProperty,(New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Colors]::Black)))))

        $combo.ItemContainerStyle = $comboItemStyle

        $dataGrid.Foreground = 'Black'
        $dataGrid.Background = 'White'
        $dataGrid.RowBackground = 'White'
        $dataGrid.AlternatingRowBackground = 'AliceBlue'

        $headerStyle.Setters.Add((New-Object System.Windows.Setter($bgProperty,(New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(230,230,230))))))
        $headerStyle.Setters.Add((New-Object System.Windows.Setter($fgProperty,(New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Colors]::Black)))))

        $dataGrid.ColumnHeaderStyle = $headerStyle

        $toggleDarkModeBtn.Content = "Dark Mode"

        # Animate the first gradient stop offset
        $animation = New-Object System.Windows.Media.Animation.DoubleAnimation(0.0,1.0,(New-Object System.Windows.Duration([System.TimeSpan]::FromSeconds(5))))
        $animation.AutoReverse = $true
        $animation.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
        $stop1.BeginAnimation([System.Windows.Media.GradientStop]::OffsetProperty, $animation)
    }
}

$filterTimer = New-Object System.Windows.Threading.DispatcherTimer
$filterTimer.Interval = [TimeSpan]::FromMilliseconds(300)
$null = $filterTimer.Add_Tick({
    $filterTimer.Stop()
    Apply-Filter
})

$combo.Add_SelectionChanged({
    Apply-Filter
})

$filterBox.Add_TextChanged({
    $filterTimer.Stop()
    $filterTimer.Start()
})

$clearFilter.Add_Click({
    $filterBox.Text = ""
    Apply-Filter
})

$toggleDarkModeBtn.Add_Click({
    $global:isDarkMode = -not $global:isDarkMode
    Apply-Theme $global:isDarkMode
})

Apply-Theme $global:isDarkMode

$window.Content = $dockPanel
$null = $window.ShowDialog()
