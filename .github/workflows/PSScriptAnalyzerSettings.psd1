@{
    ExcludeRules = @(
        'PSUseBOMForUnicodeEncodedFile',
        'PSUseToExportFieldsInManifest'
    )
    Rules = @{
        PSAvoidExclaimOperator = @{
            Enable = $true
        }
        AvoidUsingDoubleQuotesForConstantString = @{
            Enable = $true
        }
        UseCorrectCasing = @{
            Enable = $true
        }
    }
}
