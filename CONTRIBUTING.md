# Contributing to the Active Directory PowerShell Script for Cisco Identity Intelligence

First off, thank you for considering contributing to the Active Directory PowerShell Script for Cisco Identity Intelligence. It's contributions from individuals like you that help improve and expand the utility of this open-source tool for the community.

## Introduction

### Why Read These Guidelines?

Following these guidelines helps to ensure a smooth and efficient collaboration process. By adhering to these standards, you respect the time of the developers managing and maintaining this project. In return, we commit to providing timely feedback, assessing your changes fairly, and assisting you in finalizing your contributions.

### What Kinds of Contributions Are We Looking For?

We welcome all forms of contributions! Whether you're a seasoned PowerShell developer or new to open source, your input is valuable. Here are some ways you can contribute:

*   **Code Contributions**:
    *   Bug fixes: Identify and resolve issues in the existing scripts.
    *   Feature enhancements: Add new functionalities that align with the project's goals (e.g., improved data collection, new classification methods).
    *   Performance optimizations: Improve the efficiency and speed of the scripts.
*   **Documentation Improvements**:
    *   Enhance existing README.md content.
    *   Create new documentation for specific features or common use cases.
    *   Improve clarity, examples, or troubleshooting guides.
*   **Bug Reports**: Submit clear and detailed reports for any issues you encounter.
*   **Feature Suggestions**: Propose new ideas or enhancements that could benefit the script.
*   **Testing**: Help validate bug fixes or new features.

### What Kinds of Contributions Are We NOT Looking For?

*   **General Support Questions**: Please do not use the issue tracker for general support questions or troubleshooting specific to your environment that isn't clearly a bug in the script. For such inquiries, please refer to Cisco's official support channels.
*   **Security Vulnerability Disclosures (Initial Report)**: Do NOT open a public issue for security vulnerabilities. Please see the "How to Report a Bug" section for the correct procedure.

## Ground Rules

*   **Be Respectful**: Engage in discussions with respect and consideration for all community members.
*   **Maintain Quality**: All contributions, especially code, should aim for high quality, clarity, and maintainability.
*   **Test Your Changes**: If you are submitting code, ensure it includes appropriate tests (if applicable) and passes existing tests.
*   **Code Style**: Adhere to PowerShell best practices and the existing coding style of the project.
*   **Transparency**: Discuss major changes or new features transparently through issues before submitting large pull requests.
*   **Code of Conduct**: We adhere to the Cisco Code of Conduct. All participants are expected to follow it.


## Getting Started

### General Contribution Process

1.  **Fork the Repository**: Create your own fork of this repository on GitHub.
2.  **Clone Your Fork**: Clone your forked repository to your local development machine.
3.  **Create a New Branch**: Create a new branch for your changes (e.g., `feature/my-new-feature` or `bugfix/fix-issue-123`).
4.  **Make Your Changes**: Implement your bug fix, feature, or documentation improvement.
5.  **Test Your Changes**: Ensure your changes work as expected and do not introduce regressions.
6.  **Commit Your Changes**: Write clear, concise commit messages that explain your changes.
7.  **Push to Your Fork**: Push your new branch to your forked repository on GitHub.
8.  **Open a Pull Request (PR)**: Submit a Pull Request from your branch to the `main` branch of this repository.


## How to Report a Bug

### Security Disclosures

If you find a security vulnerability, **DO NOT** open an issue on GitHub. Report security bugs by emailing oss-security@cisco.com, including a detailed description of the vulnerability and steps to reproduce it. 

### Filing a Bug Report (Non-Security)

When filing a bug report, please provide as much detail as possible to help us understand and reproduce the issue. Include the following information:

*   **Script Version**: Which version of the PowerShell script are you using?
*   **Environment Details**:
    *   Operating System (e.g., Windows Server 2019)
    *   PowerShell Version (`$PSVersionTable.PSVersion`)
    *   Active Directory environment details (e.g., Domain Functional Level, Hybrid setup)
*   **Steps to Reproduce**:
    1.  What did you do? (e.g., "Ran `ADSync.ps1` with `-Preview`")
    2.  What configuration settings were in place? (e.g., "Excluded attributes were X, Y, Z. Classification rules for Admins were set to Group A.")
*   **Expected Behavior**: What did you expect to happen?
*   **Actual Behavior**: What happened instead? Include any error messages, stack traces, or relevant output.
*   **Screenshots/Logs**: Attach any relevant screenshots or log files that might help diagnose the problem.

## How to Suggest a Feature or Enhancement

If you have an idea for a new feature or an enhancement to an existing one, please open a new issue on the GitHub issue tracker. When suggesting a feature, please:

*   **Describe the Need**: Explain the problem you're trying to solve or the use case this feature would address.
*   **Propose a Solution**: Outline how you envision the feature working or how it might be implemented.
*   **Benefits**: Explain the benefits this feature would bring to users.
*   **Consider Alternatives**: Briefly mention if you've considered any alternative approaches and why you chose this one.

This information helps us understand your suggestion and assess its alignment with the project's roadmap.

## Code Review Process

All pull requests will be reviewed by project maintainers. The review process typically involves:

1.  **Initial Review**: Maintainers will review your code for functionality, style, and adherence to guidelines.
2.  **Feedback**: You may receive feedback or requests for changes. Please respond to these comments in a timely manner.
3.  **Testing**: Your changes will be tested by maintainers or automated systems.
4.  **Approval and Merge**: Once the changes are approved and all checks pass, your pull request will be merged into the `main` branch.

We aim to review pull requests within a reasonable timeframe, but response times may vary depending on the complexity of the contribution and maintainer availability.

## License

By contributing to this project, you agree that your contributions will be licensed under the Apache2 license.
