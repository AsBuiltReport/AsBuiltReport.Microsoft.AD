# AsBuiltReport.Microsoft.AD Tests

This directory contains Pester tests for the AsBuiltReport.Microsoft.AD module.

## Prerequisites

Before running the tests, ensure you have the following installed:

- **PowerShell 5.1** or later (PowerShell 7+ recommended)
- **Pester 5.0** or later
- **AsBuiltReport.Core** module (version 1.5.0 or later)

### Installing Pester

```powershell
# Install Pester 5.x
Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck
```

## Running the Tests

### Run All Tests

To run all tests in this directory:

```powershell
# From the repository root
Invoke-Pester -Path .\Tests\

# Or from within the Tests directory
Invoke-Pester
```

### Run Tests with Code Coverage

To run tests with code coverage analysis:

```powershell
$configuration = [PesterConfiguration]::Default
$configuration.Run.Path = '.\Tests\'
$configuration.CodeCoverage.Enabled = $true
$configuration.CodeCoverage.Path = '.\AsBuiltReport.Microsoft.AD\*.ps*1', '.\AsBuiltReport.Microsoft.AD\Src\**\*.ps1'
$configuration.Output.Verbosity = 'Detailed'

Invoke-Pester -Configuration $configuration
```

### Run Specific Test Contexts

To run specific test contexts:

```powershell
# Run only Module Manifest tests
Invoke-Pester -Path .\Tests\ -TagFilter 'Manifest'

# Run only Syntax tests
Invoke-Pester -Path .\Tests\ -FullNameFilter '*Syntax*'
```

## Test Structure

The test suite is organized into the following sections:

### AsBuiltReport.Microsoft.AD Module Tests

1. **Module Manifest**
   - Validates module metadata (name, GUID, version, author)
   - Checks required modules and dependencies
   - Verifies exported functions
   - Validates URIs and tags

2. **Module Structure**
   - Verifies folder hierarchy (Src, Public, Private, Language)
   - Checks for required files (psm1, psd1, json)
   - Validates presence of private functions

3. **Public Functions**
   - Confirms exported functions are accessible
   - Validates function count

4. **Function Parameter Validation**
   - Checks required parameters
   - Validates parameter types
   - Confirms parameter attributes

5. **Help Content**
   - Ensures comment-based help exists
   - Validates synopsis and description
   - Checks for related links

6. **Private Functions**
   - Validates naming conventions
   - Checks for required AD resource functions
   - Confirms newly added functions (e.g., LogAnalyticsWorkspace)

7. **JSON Configuration**
   - Validates JSON structure
   - Checks for required sections (Report, Options, Filter, InfoLevel, HealthCheck)
   - Verifies resource-specific configurations

### Module File Syntax and Quality

1. **PowerShell Script Files**
   - Validates PowerShell syntax in all .ps1 and .psm1 files
   - Uses PSParser to detect syntax errors

2. **Language Files** (Comprehensive Localization Testing)
   - Validates all localization .psd1 files are loadable
   - **Automatically tests ALL Get-AbrAz* functions have localization sections**
   - **Dynamically parses each function to find ALL $LocalizedData.* references**
   - **Verifies every referenced property exists in the localization file**
   - Tests hashtable keys using $LocalizedData are defined
   - Validates common required strings (InfoLevel, Collecting, Heading, Name, ResourceGroup, Location)
   - Checks module-wide localization sections (InvokeAsBuiltReportMicrosoftAzure, GetCountryName)

   **This comprehensive approach automatically catches missing localization strings without needing to manually add tests for each function.**

3. **Code Style and Standards**
   - Ensures comment-based help in public functions
   - Validates CmdletBinding attributes
   - Confirms try/catch error handling in private functions

## Continuous Integration

These tests are designed to run in CI/CD pipelines. They can be integrated with:

- **GitHub Actions**
- **Azure DevOps Pipelines**
- **AppVeyor**
- **Jenkins**

### Example GitHub Actions Workflow

```yaml
name: Pester Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install Pester
        shell: pwsh
        run: Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck

      - name: Install AsBuiltReport.Core
        shell: pwsh
        run: Install-Module -Name AsBuiltReport.Core -MinimumVersion 1.5.0 -Force

      - name: Run Pester Tests
        shell: pwsh
        run: |
          $config = [PesterConfiguration]::Default
          $config.Run.Path = '.\Tests\'
          $config.Output.Verbosity = 'Detailed'
          Invoke-Pester -Configuration $config
```

## Troubleshooting

### Module Not Found

If you receive errors about the module not being found:

```powershell
# Ensure you're running from the correct directory
# The tests expect to be in the Tests folder with the module folder at ..\AsBuiltReport.Microsoft.Azure\
```

### Localization Tests Failing

The localization tests automatically scan ALL private functions and verify that every `$LocalizedData.*` reference has a corresponding entry in the localization file. If these tests fail:

**Example Error:**
```
Function Get-AbrAzLoadBalancer references $LocalizedData.ProvisioningState which should exist in 'GetAbrAzLoadBalancer' localization section
```

**How to Fix:**

1. **Identify the function and property**: The error message tells you which function (e.g., `Get-AbrAzLoadBalancer`) and which property (e.g., `ProvisioningState`)

2. **Open the localization file**: `Language\en-US\MicrosoftAzure.psd1`

3. **Find the corresponding section**: Convert the function name from `Get-AbrAzLoadBalancer` to `GetAbrAzLoadBalancer` (remove hyphens)

4. **Add the missing property**:
   ```powershell
   GetAbrAzLoadBalancer = ConvertFrom-StringData @'
       Name = Name
       ResourceGroup = Resource Group
       ProvisioningState = Provisioning State  # Add this line
   '@
   ```

5. **Re-run the tests** to verify the fix

**Common Issues:**
- Typo in the property name in the function code
- Forgot to add the localization string after adding a new property
- Section name doesn't match the function name (remember to remove hyphens)

### Syntax Errors

If syntax tests fail:

```powershell
# Review the specific file mentioned in the error
# Use a PowerShell-aware editor (VS Code with PowerShell extension) to identify syntax issues
```

## Contributing

When adding new features or functions to the module:

1. **Add your new Get-AbrAz* function** to `Src/Private/`
2. **Add localization strings** to `Language/en-US/MicrosoftAzure.psd1`
   - Create a new section named after your function (e.g., `GetAbrAzLogAnalyticsWorkspace`)
   - Add all required properties (InfoLevel, Collecting, Heading, Name, ResourceGroup, Location, etc.)
3. **Run the tests** - The comprehensive localization tests will automatically:
   - Detect your new function
   - Parse all `$LocalizedData.*` references in your code
   - Verify all referenced properties exist in the localization file
   - **No need to manually add tests for each localization string!**
4. **Fix any failures** - If the tests fail, add the missing localization strings
5. Ensure all existing tests still pass
6. Follow the existing code patterns and naming conventions
7. Run tests locally before submitting a pull request

### Why Comprehensive Testing Matters

The comprehensive localization tests would have **automatically caught** the `ProvisioningState` and `Tier` issue in `Get-AbrAzLoadBalancer` before it reached production. This saves debugging time and ensures all localization strings are present.

## Additional Resources

- [Pester Documentation](https://pester.dev/)
- [AsBuiltReport.Core Repository](https://github.com/AsBuiltReport/AsBuiltReport.Core)
- [PowerShell Testing Best Practices](https://pester.dev/docs/usage/test-file-structure)
