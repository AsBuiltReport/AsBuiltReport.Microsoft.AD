function Get-ColumnChart {
    <#
    .SYNOPSIS
        Generates a column chart based on the provided sample data.

    .DESCRIPTION
        The Get-ColumnChart function creates a column chart using the provided sample data array.
        You can specify the chart name, X-axis title, and Y-axis title.

    .PARAMETER SampleData
        An array of sample data to be used for generating the column chart. This parameter is mandatory.

    .PARAMETER ChartName
        The name of the chart. This parameter is optional.

    .PARAMETER AxisXTitle
        The title for the X-axis of the chart. This parameter is optional.

    .PARAMETER AxisYTitle
        The title for the Y-axis of the chart. This parameter is optional.

    .OUTPUTS
        System.String
        Returns a string representation of the generated column chart.

    .EXAMPLE
        $data = @(1, 2, 3, 4, 5)
        Get-ColumnChart -SampleData $data -ChartName "Sample Chart" -AxisXTitle "X Axis" -AxisYTitle "Y Axis"

    .NOTES
        Author: Your Name
        Date: Today's Date
    #>

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter (
            Position = 0,
            Mandatory,
            HelpMessage = "Provide the sample data as an array."
        )]
        [System.Array]
        $SampleData,

        [Parameter (
            HelpMessage = "Specify the name of the chart."
        )]
        [String]
        $ChartName,

        [Parameter (
            HelpMessage = "Specify the title for the X axis."
        )]
        [String]
        $AxisXTitle,

        [Parameter (
            HelpMessage = "Specify the title for the Y axis."
        )]
        [String]
        $AxisYTitle,

        [Parameter (
            HelpMessage = "Specify the field for the X axis."
        )]
        [String]
        $XField,

        [Parameter (
            HelpMessage = "Specify the field for the Y axis."
        )]
        [String]
        $YField,

        [Parameter (
            HelpMessage = "Specify the name of the chart area."
        )]
        [String]
        $ChartAreaName,

        [Parameter (
            HelpMessage = "Specify the name of the chart title."
        )]
        [String]
        $ChartTitleName = '',

        [Parameter (
            HelpMessage = "Specify the text for the chart title."
        )]
        [String]
        $ChartTitleText = ' ',

        [Parameter (
            HelpMessage = "Specify the width of the chart."
        )]
        [int]
        $Width = 600,

        [Parameter (
            HelpMessage = "Specify the height of the chart."
        )]
        [int]
        $Height = 400,

        [Parameter (
            HelpMessage = "Specify whether to reverse the color palette."
        )]
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
        Name = $ChartAreaName
        AxisXTitle = $AxisXTitle
        AxisYTitle = $AxisYTitle
        NoAxisXMajorGridLines = $true
        NoAxisYMajorGridLines = $true
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
    $sampleData | Add-ColumnChartSeries @addChartSeriesParams

    $addChartTitleParams = @{
        Chart = $exampleChart
        ChartArea = $exampleChartArea
        Name = $ChartTitleName
        Text = $ChartTitleText
        Font = New-Object -TypeName 'System.Drawing.Font' -ArgumentList @('Segoe Ui', '12', [System.Drawing.FontStyle]::Bold)
    }
    Add-ChartTitle @addChartTitleParams

    $TempPath = Resolve-Path ([System.IO.Path]::GetTempPath())

    $ChartImage = Export-Chart -Chart $exampleChart -Path $TempPath.Path -Format "PNG" -PassThru

    if ($PassThru) {
        Write-Output -InputObject $chartFileItem
    }

    $ChartImageByte = switch ($PSVersionTable.PSEdition) {
        'Desktop' { Get-Content $ChartImage -Encoding byte }
        'Core' { Get-Content $ChartImage -AsByteStream -Raw }
    }

    $Base64Image = [convert]::ToBase64String($ChartImageByte)

    Remove-Item -Path $ChartImage.FullName

    return $Base64Image

} # end
