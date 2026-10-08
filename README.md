## Agent Sandbox Sharing Violation Resolver for Windows

### The Problem
Developers building and running agentic AI systems on Windows frequently encounter "sharing violation" errors during sandbox setup or runtime validation. This issue typically arises when the agent's environment attempts to create or modify files/directories that are already in use by another process, or when security software (like antivirus) locks them. This prevents the agent from initializing its secure execution environment, rendering it unable to operate correctly. This is a significant blocker for reliable agent development and deployment on Windows.

### Why this Project Shape/Stack?
This project is a small, focused C# console application. C# was chosen because it provides direct access to Windows API calls necessary for robust file and process management, and it's a native Windows solution, making it ideal for addressing Windows-specific file system issues. A console application allows for easy integration into existing build scripts, agent orchestration frameworks, or as a standalone diagnostic tool. The goal is to provide a pre-flight check and remediation utility.

### Setup and Usage (Zero API Keys Required)

This tool does not involve LLMs directly, as it addresses a purely infrastructural problem.

**Prerequisites:**
* .NET 8 SDK (or later)

**Setup:**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/agent-sandbox-fixer.git
    cd agent-sandbox-fixer
    ```

2.  **Build the application:**
    ```bash
    dotnet build -c Release
    ```

**Usage:**

The tool attempts to identify and release locks on a specified path. It takes one argument: the path to the sandbox directory that is causing issues.

1.  **Run the tool with a problematic sandbox path:**
    ```bash
    dotnet run --project AgentSandboxFixer -- <path-to-your-sandbox-directory>
    ```
    For example, if your agent's sandbox is failing to initialize in `C:\Users\User\AppData\Local\Temp\AgentSandbox123`:
    ```bash
    dotnet run --project AgentSandboxFixer -- C:\Users\User\AppData\Local\Temp\AgentSandbox123
    ```

    The tool will attempt to:
    *   List processes that might be holding locks on files within the specified directory.
    *   Offer to terminate processes (if possible and safe) that are known to interfere.
    *   Provide guidance if it cannot resolve the issue directly (e.g., suggesting an antivirus exclusion).

    **Important:** Use with caution. Terminating processes can lead to data loss or system instability if done indiscriminately. This tool will prompt for confirmation before attempting to terminate any process.

### Optional Real-LLM Adapter
Not applicable. This tool focuses on Windows file system and process management, not LLM interaction.
