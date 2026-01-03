function Get-PieChart {
    <#
    .SYNOPSIS
    Used by As Built Report to generate PScriboChart pie charts.

    .DESCRIPTION
    The Get-PieChart function generates a pie chart using the PScriboChart module. It accepts various parameters to customize the chart, such as sample data, chart name, fields for the X and Y axes, legend name and alignment, chart title, dimensions, and palette options. The function returns the pie chart as a Base64-encoded string.

    .PARAMETER SampleData
    An array of data to be used for generating the pie chart.

    .PARAMETER ChartName
    The name of the chart.

    .PARAMETER XField
    The field to be used for the X-axis.

    .PARAMETER YField
    The field to be used for the Y-axis.

    .PARAMETER ChartLegendName
    The name of the chart legend.

    .PARAMETER ChartLegendAlignment
    The alignment of the chart legend. Default is 'Center'.

    .PARAMETER ChartTitleName
    The name of the chart title. Default is a space character.

    .PARAMETER ChartTitleText
    The text of the chart title. Default is a space character.

    .PARAMETER Width
    The width of the chart in pixels. Default is 600.

    .PARAMETER Height
    The height of the chart in pixels. Default is 400.

    .PARAMETER ReversePalette
    A boolean indicating whether to reverse the color palette. Default is $false.

    .EXAMPLE
    $sampleData = @(
        @{ Category = 'A'; Value = 10 },
        @{ Category = 'B'; Value = 20 },
        @{ Category = 'C'; Value = 30 }
    )
    Get-PieChart -SampleData $sampleData -ChartName 'ExampleChart' -XField 'Category' -YField 'Value' -ChartLegendName 'Legend'

    .LINK
    https://github.com/iainbrighton/PScriboCharts
    #>

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter (
            Position = 0,
            Mandatory,
            HelpMessage = 'An array of data to be used for generating the pie chart.')]
        [System.Array]
        $SampleData,
        [Parameter (
            HelpMessage = 'The name of the chart.')]
        [String]
        $ChartName,
        [Parameter (
            HelpMessage = 'The field to be used for the X-axis.')]
        [String]
        $XField,
        [Parameter (
            HelpMessage = 'The field to be used for the Y-axis.')]
        [String]
        $YField,
        [Parameter (
            HelpMessage = 'The name of the chart legend.')]
        [String]
        $ChartLegendName,
        [Parameter (
            HelpMessage = 'The alignment of the chart legend. Default is Center.')]
        [String]
        $ChartLegendAlignment = 'Center',
        [Parameter (
            HelpMessage = 'The name of the chart title. Default is a space character.')]
        [String]
        $ChartTitleName = ' ',
        [Parameter (
            HelpMessage = 'The text of the chart title. Default is a space character.')]
        [String]
        $ChartTitleText = ' ',
        [Parameter (
            HelpMessage = 'The width of the chart in pixels. Default is 600.')]
        [int]
        $Width = 600,
        [Parameter (
            HelpMessage = 'The height of the chart in pixels. Default is 400.')]
        [int]
        $Height = 400,
        [Parameter (
            HelpMessage = 'A boolean indicating whether to reverse the color palette. Default is $false.')]
        [bool]
        $ReversePalette = $false
    )

    $AbrCustomPalette = @(
        [System.Drawing.ColorTranslator]::FromHtml('#355780')
        [System.Drawing.ColorTranslator]::FromHtml('#48678f')
        [System.Drawing.ColorTranslator]::FromHtml('#5b789e')
        [System.Drawing.ColorTranslator]::FromHtml('#6e89ae')
        [System.Drawing.ColorTranslator]::FromHtml('#809bbe')
        [System.Drawing.ColorTranslator]::FromHtml('#94acce')
        [System.Drawing.ColorTranslator]::FromHtml('#a7bfde')
        [System.Drawing.ColorTranslator]::FromHtml('#bbd1ee')
        [System.Drawing.ColorTranslator]::FromHtml('#cfe4ff')
    )

    $exampleChart = New-Chart -Name $ChartName -Width $Width -Height $Height -BorderColor 'DarkBlue' -BorderStyle Dash -BorderWidth 1

    $addChartAreaParams = @{
        Chart = $exampleChart
        Name = 'exampleChartArea'
        AxisXInterval = 1
    }
    $exampleChartArea = Add-ChartArea @addChartAreaParams -PassThru

    $addChartSeriesParams = @{
        Chart = $exampleChart
        ChartArea = $exampleChartArea
        Name = 'exampleChartSeries'
        XField = $XField
        YField = $YField
        CustomPalette = $AbrCustomPalette
        ColorPerDataPoint = $true
        ReversePalette = $ReversePalette
    }
    $sampleData | Add-PieChartSeries @addChartSeriesParams

    $addChartLegendParams = @{
        Chart = $exampleChart
        Name = $ChartLegendName
        TitleAlignment = $ChartLegendAlignment
    }
    Add-ChartLegend @addChartLegendParams

    $addChartTitleParams = @{
        Chart = $exampleChart
        ChartArea = $exampleChartArea
        Name = $ChartTitleName
        Text = $ChartTitleText
        Font = New-Object -TypeName 'System.Drawing.Font' -ArgumentList @('Segoe Ui', '12', [System.Drawing.FontStyle]::Bold)
    }
    Add-ChartTitle @addChartTitleParams

    $TempPath = Resolve-Path ([System.IO.Path]::GetTempPath())

    $ChartImage = Export-Chart -Chart $exampleChart -Path $TempPath.Path -Format 'PNG' -PassThru

    $ChartImageByte = switch ($PSVersionTable.PSEdition) {
        'Desktop' { Get-Content $ChartImage -Encoding byte }
        'Core' { Get-Content $ChartImage -AsByteStream -Raw }
    }

    $Base64Image = [convert]::ToBase64String($ChartImageByte)

    Remove-Item -Path $ChartImage.FullName

    return $Base64Image

} # end