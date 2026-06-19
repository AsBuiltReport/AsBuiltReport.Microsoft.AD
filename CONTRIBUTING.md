# Contributing to AsBuiltReport

Your contribution is welcomed and appreciated! Thank you for taking the time to contribute to this project.

Please take a moment to review this document to make the contribution process easy and effective for everyone involved.

Following these guidelines helps to communicate that you respect the time of the developers managing and developing this open source project. In return, they should reciprocate that respect in addressing your issue or assessing patches and features.

## Ways to Contribute

Contributing to this project is as easy as:

- Reporting bugs and issues
- Proposing new features
- Discussing the current state of the code
- Submitting fixes and improvements
- Creating new report modules
- Improving documentation

For comprehensive contribution guidelines, please visit our [Developer Guide](https://www.asbuiltreport.com/dev-guide/contributing).

## Getting Started

### Prerequisites

- A [GitHub account](https://github.com/signup/free)
- Git installed on your local machine
- PowerShell 5.1 or PowerShell 7+
- [Visual Studio Code](https://code.visualstudio.com/) (recommended)

### Learning Resources

If you're new to Git and GitHub:

- [GitHub's guide on Forking](https://docs.github.com/pull-requests/collaborating-with-pull-requests/working-with-forks/about-forks)
- [GitHub's guide on Contributing to Open Source](https://docs.github.com/get-started/exploring-projects-on-github/finding-ways-to-contribute-to-open-source-on-github)
- [Understanding the GitHub Flow](https://docs.github.com/get-started/quickstart/github-flow)

## Using the Issue Tracker

The issue tracker is the preferred channel for bug reports, feature requests, and submitting pull requests. Please respect the following:

- **Do not** use the issue tracker for personal support requests. Use our [Discussion Board](https://github.com/orgs/AsBuiltReport/discussions) instead.
- **Do not** derail or troll issues. Keep discussions on topic and respect the opinions of others.
- Search existing issues (both open and closed) before creating a new one to avoid duplicates.

## Reporting Bugs

A bug is a demonstrable problem that is caused by the code in the repository. Good bug reports are extremely helpful!

### Before Submitting a Bug Report

Please perform the following due diligence:

1. **Read the documentation** - Check the `README` in the AsBuiltReport.Microsoft.Azure repository, including Supported Versions, System Requirements, and Module Installation sections.
2. **Update to the latest version** - Your issue may already be fixed in the most recent release.
3. **Check dependencies** - Try upgrading or downgrading vendor PowerShell modules if applicable.
4. **Use the `-Verbose` parameter** - This may help identify the issue.
5. **Test with InfoLevels** - Set all InfoLevels to 0 in your report config, then gradually increase them to isolate the problem.
6. **Try older versions** - If you're on the latest release, try rolling back to see if the problem exists in earlier versions.
7. **Search existing issues** - Make sure it's not a known issue.

### What to Include in Bug Reports

A good bug report should include:

- A quick summary and/or background of the issue
- Software versions:
  - AsBuiltReport module versions (e.g., AsBuiltReport.Core v1.4.3)
  - PowerShell version (e.g., Windows PowerShell 5.1 or PowerShell 7.4)
  - Operating System (e.g., Windows Server 2022)
- Steps to reproduce:
  - Be specific
  - Provide the full command line you executed
  - Include sample code if applicable
  - Upload screenshots if helpful
- What you expected to happen
- What actually happened
- Additional notes (why you think this might be happening, troubleshooting steps you've tried)

## Feature Requests

Feature requests are welcome! Please provide as much detail and context as possible about:

- The problem you're trying to solve
- Why this feature would be valuable
- How you envision it working
- Any examples from other tools or projects

It's up to you to make a strong case for the merits of this feature. Keep in mind that features should fit within the scope and aims of the project.

## Pull Requests

Good pull requests (patches, improvements, new features) are a fantastic help. They should remain focused in scope and avoid containing unrelated commits.

**Please ask first** before embarking on any significant pull request (e.g., implementing features, refactoring code), otherwise you risk spending time on something that might not be merged.

### Creating Quality Pull Requests

A good quality pull request will have:

- **A meaningful title** describing what change you're making (not just "Fix issue #5")
  - Use present tense and imperative mood: "Add support for Server 2022" not "Added support"
  - "Fix connection timeout" not "Fixed for connection issue"
- **A clear description** summarizing the changes and their benefits
  - Reference related issues (e.g., "Fix #11")
  - First sentence should explain the benefit to end users
- **Focused scope** - Avoid PRs with too many changes; split large features into smaller PRs
- **Updated documentation**:
  - Update `CHANGELOG.md` with add/remove/fix/change information
  - Update `README.md` with new features, instructions, parameters, or examples
- **Well-written commits** that tell the story of the development
- **Code quality** meeting project best practices

### Submitting Pull Requests

Always create pull requests against the `dev` branch:

1. Fork the AsBuiltReport repository

2. Clone your fork and add the upstream remote:
   ```bash
   git clone https://github.com/<your-username>/AsBuiltReport.Microsoft.Azure
   cd AsBuiltReport.Microsoft.Azure
   git remote add upstream https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.Azure
   ```

3. Create a new feature branch from `dev`:
   ```bash
   git checkout dev
   git pull upstream dev
   git checkout -b <feature-branch-name>
   ```

4. Make your changes and commit with clear messages

5. Update documentation (`CHANGELOG.md` and `README.md`)

6. Squash commits into one or two succinct commits if needed:
   ```bash
   git rebase -i HEAD~n  # n being the number of commits to rebase
   ```

7. Ensure your branch is up to date with upstream:
   ```bash
   git fetch upstream
   git rebase upstream/dev
   ```

8. Push your branch to your fork:
   ```bash
   git push --force origin <feature-branch-name>
   ```

9. [Open a Pull Request](https://help.github.com/articles/using-pull-requests/) against the `dev` branch

Pull requests will be reviewed as soon as possible. Please follow the PR template provided in the repository.

## Code Contributions

### Code Editor

We highly recommend using [Visual Studio Code](https://code.visualstudio.com/) for development.

### Coding Standards

Code contributors should follow the [PowerShell Best Practices and Style Guide](https://github.com/PoshCode/PowerShellPracticeAndStyle) to ensure consistency.

Use [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) to check code quality.

### DO

- Use PascalCasing for all public member, type, and namespace names
- Use custom label headers within tables for readability
- Favor readability over brevity
- Use PSCustomObjects to store data for PScribo tables:
  ```powershell
  $myObject = [PSCustomObject]@{
      Name = 'Value'
      Property = 'Value'
  }

  $TableParams = @{
      Name = 'Table Name'
      List = $true
      ColumnWidths = 40, 60
  }

  if ($Report.ShowTableCaptions) {
      $TableParams['Caption'] = "- $($TableParams.Name)"
  }

  $myObject | Table @TableParams
  ```
- Set ColumnWidths for all tables (list tables typically use 40, 60)
- Sort primary object properties in alphanumeric order
- Perform all safe commands (Get-*, API calls) at the start of scripts
- Use comments in English to explain reasoning, not to describe commands
- Maintain a changelog following [Keep a Changelog](https://keepachangelog.com/) guidelines

### DO NOT

- Include functions within report scripts (create separate files in `\Src\Private`)
- Submit unrelated changes in the same pull request

## Version Control Branching

- Always create a new branch for your work
- Base your branch off `dev`
- Avoid submitting unrelated changes (bug fixes & new features) in the same branch

## Questions and Discussion

If you have questions or want to discuss contributions:

- Raise an issue in the AsBuiltReport.Microsoft.Azure [repository](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.Azure)
- Email us at support@asbuiltreport.com
- Visit our website at [www.asbuiltreport.com](https://www.asbuiltreport.com)

## License

By submitting a patch, you agree to allow the project owner to license your work under the [MIT License](https://www.asbuiltreport.com/about/license/).
