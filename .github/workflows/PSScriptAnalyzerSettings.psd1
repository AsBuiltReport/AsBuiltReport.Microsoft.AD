@{
    ExcludeRules = @(
        'PSUseToExportFieldsInManifest'
        'PSAvoidUsingWriteHost'
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
        PSAvoidUsingCmdletAliases = @{
            Enable = $true
        }
        PSUseConsistentWhitespace = @{
            Enable = $true
        }
    }
}
