using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace AgentSandboxFixer
{
    public class Program
    {
        // P/Invoke declarations for Windows API functions
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;

        public static void Main(string[] args)
        {
            Console.WriteLine("Agent Sandbox Sharing Violation Resolver");
            Console.WriteLine("---------------------------------------");

            if (args.Length == 0)
            {
                Console.WriteLine("Usage: AgentSandboxFixer <path-to-sandbox-directory>");
                Console.WriteLine("Example: AgentSandboxFixer C:\\Users\\User\\AppData\\Local\\Temp\\AgentSandbox123");
                return;
            }

            string sandboxPath = args[0];

            if (!Directory.Exists(sandboxPath))
            {
                Console.WriteLine($"Error: Directory '{sandboxPath}' does not exist.");
                return;
            }

            Console.WriteLine($"Attempting to diagnose sharing violations for: {sandboxPath}");

            // First, try to access a dummy file to see if the directory itself is locked
            string testFilePath = Path.Combine(sandboxPath, $"_test_lock_{Guid.NewGuid()}.tmp");
            IntPtr fileHandle = IntPtr.Zero;
            try
            {
                // Try to create a file with no sharing, which would fail if the directory is locked
                fileHandle = CreateFile(testFilePath, GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (fileHandle == new IntPtr(-1))
                {
                    // File creation failed, try to create with sharing modes
                    fileHandle = CreateFile(testFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                }

                if (fileHandle != new IntPtr(-1) && fileHandle != IntPtr.Zero)
                {
                    Console.WriteLine("Initial check: Directory seems accessible. Trying to find specific file locks...");
                    CloseHandle(fileHandle);
                    File.Delete(testFilePath); // Clean up test file
                }
                else
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine($"Initial check: Directory might be locked. Win32 Error Code: {errorCode}");
                    if (errorCode == 32) // ERROR_SHARING_VIOLATION
                    {
                        Console.WriteLine("This indicates a sharing violation at the directory level.");
                        DiagnoseAndSuggestRemediation(sandboxPath);
                        return;
                    }
                    else if (errorCode == 5) // ERROR_ACCESS_DENIED
                    {
                        Console.WriteLine("Access Denied. Run this tool as Administrator if the sandbox path requires elevated permissions.");
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred during initial directory access check: {ex.Message}");
            }
            finally
            {
                if (fileHandle != IntPtr.Zero && fileHandle != new IntPtr(-1))
                {
                    CloseHandle(fileHandle);
                }
                if (File.Exists(testFilePath))
                {
                    File.Delete(testFilePath);
                }
            }

            // Iterate through files in the directory to find specific locks
            FindLockedFiles(sandboxPath);
        }

        private static void FindLockedFiles(string path)
        {
            Console.WriteLine($"Searching for locked files within '{path}' and its subdirectories...");

            try
            {
                foreach (string file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                {
                    if (IsFileLocked(file))
                    {
                        Console.WriteLine($"Found potentially locked file: {file}");
                        DiagnoseAndSuggestRemediation(file);
                    }
                }
                Console.WriteLine("Scan complete. If no specific locks were identified, the issue might be transient or process-level.");
                Console.WriteLine("Consider checking Task Manager for processes consuming high CPU/disk in the sandbox path, or security software.");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"Access denied to '{path}' or a subdirectory. Please run as Administrator.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while scanning for locked files: {ex.Message}");
            }
        }

        private static bool IsFileLocked(string file)
        {
            IntPtr fileHandle = IntPtr.Zero;
            try
            {
                // Attempt to open the file with exclusive access (no sharing)
                // If this succeeds, the file is NOT locked by another process (in a way that prevents exclusive access)
                // If it fails with ERROR_SHARING_VIOLATION (32), then it is locked.
                fileHandle = CreateFile(file, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

                if (fileHandle == new IntPtr(-1))
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    if (errorCode == 32) // ERROR_SHARING_VIOLATION
                    {
                        return true;
                    }
                    else if (errorCode == 5) // ERROR_ACCESS_DENIED
                    {
                        // File might be locked, or we just don't have permission to check it.
                        // For this tool's purpose, we'll treat it as potentially locked if we can't get access.
                        Console.WriteLine($"Warning: Access denied to check file '{file}'. Might be locked or permission issue. Error Code: {errorCode}");
                        return true;
                    }
                    else
                    {
                        // Other errors, assume not locked in a way we can detect
                        return false;
                    }
                }
                return false; // Successfully opened, so not locked for exclusive access
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking file '{file}': {ex.Message}");
                return false;
            }
            finally
            {
                if (fileHandle != IntPtr.Zero && fileHandle != new IntPtr(-1))
                {
                    CloseHandle(fileHandle);
                }
            }
        }

        private static void DiagnoseAndSuggestRemediation(string path)
        {
            Console.WriteLine($"\n--- Remediation Suggestions for: {path} ---");

            // Look for common culprits: VS Code, anti-virus, indexing services, previous agent runs
            Process[] processes = Process.GetProcesses();
            bool foundPotentialCulprit = false;

            foreach (Process p in processes)
            {
                try
                {
                    // Check if process name or main window title suggests it's related
                    string processName = p.ProcessName.ToLowerInvariant();
                    string mainWindowTitle = p.MainWindowTitle.ToLowerInvariant();

                    // This is a heuristic. A more robust solution would involve Windows Restart Manager API or similar.
                    if (processName.Contains("code") || processName.Contains("explorer") ||
                        processName.Contains("antivirus") || processName.Contains("scanner") ||
                        processName.Contains("indexing") || processName.Contains("search") ||
                        processName.Contains("python") || processName.Contains("node") ||
                        mainWindowTitle.Contains(path.ToLowerInvariant()))
                    {
                        Console.WriteLine($"Potential culprit process: PID={p.Id}, Name='{p.ProcessName}', Title='{p.MainWindowTitle}'");
                        foundPotentialCulprit = true;

                        Console.Write("Attempt to terminate this process? (y/N): ");
                        string response = Console.ReadLine()?.ToLowerInvariant();
                        if (response == "y")
                        {
                            try
                            {
                                p.Kill();
                                Console.WriteLine($"Process PID {p.Id} ({p.ProcessName}) terminated.");
                                Thread.Sleep(1000); // Give system time to release handles
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Failed to terminate process PID {p.Id}: {ex.Message}");
                                Console.WriteLine("You may need to terminate it manually via Task Manager.");
                            }
                        }
                    }
                }
                catch (InvalidOperationException) { /* Process might have exited */ }
                catch (System.ComponentModel.Win32Exception) { /* Access denied to process info */ }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error inspecting process PID {p.Id}: {ex.Message}");
                }
            }

            if (!foundPotentialCulprit)
            {
                Console.WriteLine("No obvious process culprits found by name/title heuristic.");
            }

            Console.WriteLine("\nGeneral Remediation Steps:");
            Console.WriteLine("1. Ensure no other applications (IDEs, file explorers, command prompts) have the sandbox directory open.");
            Console.WriteLine("2. Check your antivirus or security software. Temporarily disabling it or adding an exclusion for the sandbox path might help.");
            Console.WriteLine("3. Restart any agent processes or the development environment that was using the sandbox.");
            Console.WriteLine("4. Reboot your system if the issue persists, as this often clears stubborn locks.");
            Console.WriteLine("5. Run this tool again after trying these steps.");
            Console.WriteLine("-------------------------------------------\n");
        }
    }
}
