//Synopsis:
//Windows program to enable running a command (e.g. node) as a service

//Compilation:
//cl.exe /Ox /MT cmd_svc.c advapi32.lib

#include <windows.h>
#include <stdio.h>
#include <time.h>

static HANDLE processHandle = INVALID_HANDLE_VALUE;
static HANDLE shutdownEvent = NULL;
static CRITICAL_SECTION logCS;
static DWORD serviceMainId = 0;
static HANDLE serviceMainHandle = INVALID_HANDLE_VALUE;
static SERVICE_STATUS ServiceStatus;
static SERVICE_STATUS_HANDLE hStatus;
static char* cmdToRun = NULL;
static char* cmdLog = NULL;
static char* cmdLogArchive = NULL;
static char* cmdDirectory = NULL;
static DWORD cmdTimeoutSeconds = 0;
static DWORD cmdShutdownSeconds = 0;
static int cmdMaxLog = 0;
static HANDLE procStdout_read = NULL;
static HANDLE procStdout_write = NULL;
static HANDLE procStdin_read = NULL;
static HANDLE procStdin_write = NULL;
static DWORD cmdStartMs = 5000;
static DWORD procStdout_bufsize = 65535;
static int pipeFlushMs = 1000;
static int svcWaitIntervalMs = 20000;
static char procStdout_buf[65536];

void Usage()
{
	printf("\nCMD_SVC - Runs a command as a service\nv1.0 (C) Solent Technology Limited 2016\n");
	printf("\nInstall a service:\n\ncmd_svc -i service_name -c command [-l log_path] [-t timeout_seconds] [-m max_log_KB] [-g graceful_shutdown_seconds] [-d working_directory]\n");
	printf("\nRemove a service:\n\ncmd_svc -r service_name\n\n");
	ExitProcess(2);
}

void Barf()
{
	char msg[256];
	DWORD error = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), msg, 256, NULL);
	printf("\nFailed\nError %lu: %s\n", error, msg);
    ExitProcess(1);
}

void Log(char* msg, DWORD error)
{
	FILE* log;
	char errorMsg[256];
	char dateMsg[32];
	time_t now;
	struct tm *t;
	HANDLE logh;
	DWORD fileSizeHi;
	DWORD fileSizeLo;
		
	if (cmdLog)
	{
		EnterCriticalSection(&logCS);
		
		if ((cmdMaxLog > 0) && cmdLogArchive)
		{
			logh = CreateFile(cmdLog, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (logh != INVALID_HANDLE_VALUE)
			{
				fileSizeHi;
				fileSizeLo = GetFileSize(logh, &fileSizeHi);
				CloseHandle(logh);
				if ((fileSizeLo != 0xFFFFFFFF) && ((fileSizeHi > 0) || ((double)fileSizeLo / 1024.0 > (double)cmdMaxLog))) MoveFileEx(cmdLog, cmdLogArchive, MOVEFILE_REPLACE_EXISTING);
			}
		}
	
		log = fopen(cmdLog, "a+");
		if (log)
		{
			if (error == 65500) // Raw Command stdout/stderr - no banner
			{
				fprintf(log, "%s", msg);
			}
			else
			{
				now = time(NULL);
				t = (struct tm *)localtime(&now);
				strftime(dateMsg, 31, "%Y-%m-%d %H:%M:%S", t);
				if (error)
				{
					*errorMsg = 0;
					FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errorMsg, 255, NULL);
					fprintf(log, "\n==========================\n%s CMDSVC: %s, error %lu: %s\n==========================\n", dateMsg, msg, error, errorMsg);
				}
				else
				{
					fprintf(log, "\n==========================\n%s CMDSVC: %s\n==========================\n", dateMsg, msg);
				}
			}
			fclose(log);
		}
		
		LeaveCriticalSection(&logCS);
	}
}

void Shutdown()
{
	if (! SetEvent(shutdownEvent)) Log("SetEvent() failed", GetLastError());
}

BOOL WINAPI ProcessHandler(DWORD control)
{
	if (control == CTRL_SHUTDOWN_EVENT) Shutdown();
	return TRUE;
}

VOID WINAPI ServiceHandler(DWORD control)
{	
	if ((control == SERVICE_CONTROL_STOP) || (control == SERVICE_CONTROL_SHUTDOWN))	Shutdown();
}

void ReadProcessOutput()
{
	DWORD bytes = 0;
	time_t start = time(NULL);
	time_t now;
	
	do
	{
		if (! PeekNamedPipe(procStdout_read, NULL, 0, NULL, &bytes, NULL))
		{
			Log("PeekNamedPipe() failed", GetLastError());
			return;
		}
		if (bytes == 0) return;
		if (! ReadFile(procStdout_read, procStdout_buf, procStdout_bufsize, &bytes, NULL))
		{
			Log("ReadFile() failed", GetLastError());
			return;
		}
		if (bytes == 0) return;
		if (bytes > procStdout_bufsize)
		{
			Log("Bad read on pipe", 0);
			return;
		}
		*(procStdout_buf + bytes) = 0;
		Log(procStdout_buf, 65500);
		
		now = time(NULL);
	}
	while (now - start < pipeFlushMs / 1000);
}

void KillProcess(HANDLE proc)
{
	ReadProcessOutput();
	
	if (TerminateProcess(proc, 99))
		Log("Command was killed [exit code 99]", 0);
	else
		Log("Command could not be killed", GetLastError());
}

void LogSetServiceStatus(DWORD currentState)
{
	ServiceStatus.dwCurrentState = currentState;
	if (! SetServiceStatus(hStatus, &ServiceStatus)) Log("SetServiceStatus() failed", GetLastError());
}
	
void ServiceMain(int argc, char** argv)
{
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION procInfo;
	SECURITY_ATTRIBUTES secAttr;
	DWORD bytesWritten;
	BOOL launchedProcess;
	char msg[64];
	DWORD processExitCode;
	DWORD waitTimeoutMs;
	time_t startTime;
	long elapsedSeconds;
	HANDLE waitHandles[2];
	int processState;
	
	*(procStdout_buf + procStdout_bufsize) = 0;

	cmdLogArchive = malloc(strlen(cmdLog) + 6);
	if (cmdLogArchive) sprintf(cmdLogArchive, "%s.old", cmdLog);

	ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode = NO_ERROR;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = svcWaitIntervalMs;

	serviceMainId = GetCurrentThreadId();
		
	if (! DuplicateHandle(processHandle, GetCurrentThread(), processHandle, &serviceMainHandle, THREAD_ALL_ACCESS, FALSE, 0))
	{
		Log("DuplicateHandle() failed", GetLastError());
		return;
	}
	
	hStatus = RegisterServiceCtrlHandler("cmdsvc", (LPHANDLER_FUNCTION)ServiceHandler);
	if (hStatus == (SERVICE_STATUS_HANDLE) 0)
	{
		Log("RegisterServiceCtrlHandler() failed", GetLastError());
		return;
	}
	
	// Use process handler in addition to the service handler, because SERVICE_CONTROL_SHUTDOWN msg is unreliable
	if (! SetConsoleCtrlHandler(ProcessHandler, TRUE)) Log("SetConsoleCtrlHandler() failed", GetLastError());

	// Disable process termination confirmation prompt
	if (! SetProcessShutdownParameters(0x280, SHUTDOWN_NORETRY)) Log("SetProcessShutdownParameters() failed", GetLastError());
	
	LogSetServiceStatus(SERVICE_START_PENDING);
	
	if (cmdToRun)
	{
		ZeroMemory(&startupInfo, sizeof(startupInfo));
		startupInfo.cb = sizeof(startupInfo);
		ZeroMemory(&procInfo, sizeof(procInfo));
		procInfo.hProcess = INVALID_HANDLE_VALUE;
		startupInfo.dwFlags = STARTF_USESTDHANDLES;
		startupInfo.hStdOutput = INVALID_HANDLE_VALUE;
		startupInfo.hStdError = INVALID_HANDLE_VALUE;
		startupInfo.hStdInput = INVALID_HANDLE_VALUE;
	
		secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
		secAttr.bInheritHandle = TRUE;
		secAttr.lpSecurityDescriptor = NULL;
		
		if (! CreatePipe(&procStdout_read, &procStdout_write, &secAttr, 0))
		{
			Log("CreatePipe() failed", GetLastError());
			return;
		}

		if (! CreatePipe(&procStdin_read, &procStdin_write, &secAttr, 0))
		{
			Log("CreatePipe() failed", GetLastError());
			return;
		}
		
		if ( ! SetHandleInformation(procStdout_read, HANDLE_FLAG_INHERIT | SYNCHRONIZE, 0))
		{
			Log("SetHandleInformation() failed", GetLastError());
			return;
		}

		if ( ! SetHandleInformation(procStdin_write, HANDLE_FLAG_INHERIT, 0))
		{
			Log("SetHandleInformation() failed", GetLastError());
			return;
		}
		
		Log(cmdToRun, 0);
		
		startupInfo.hStdError = procStdout_write;
		startupInfo.hStdOutput = procStdout_write;
		startupInfo.hStdInput = procStdin_read;
		
		launchedProcess = CreateProcess(NULL, cmdToRun, NULL, NULL, TRUE, 0, NULL, cmdDirectory, &startupInfo, &procInfo);
		ServiceStatus.dwServiceSpecificExitCode = GetLastError();
		
		if (procInfo.hThread != INVALID_HANDLE_VALUE) CloseHandle(procInfo.hThread);
		
		if (! launchedProcess)
		{
			ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
			Log("Failed to launch command", ServiceStatus.dwServiceSpecificExitCode);
		}
		else
		{	
			startTime = time(NULL);
		
			LogSetServiceStatus(SERVICE_RUNNING);
			
			Sleep(cmdStartMs); // Nasty workaround so that service starts cleanly even for very quick commands
			
			waitHandles[0] = procInfo.hProcess;
			waitHandles[1] = shutdownEvent;
			
			processState = 1; // 1=process_running, 0=process_terminated, 2=process_requires_termination
			
			while (processState == 1)
			{
				elapsedSeconds = time(NULL) - startTime;
				if (cmdTimeoutSeconds == 0)
				{
					waitTimeoutMs = pipeFlushMs;
				}
				else if (cmdTimeoutSeconds <= elapsedSeconds)
				{
					Log("Command timed out", 0);
					processState = 2;
					break;
				}
				else
				{
					waitTimeoutMs = (cmdTimeoutSeconds - elapsedSeconds) * 1000;
					if (waitTimeoutMs > pipeFlushMs) waitTimeoutMs = pipeFlushMs;
				}
				
				switch(WaitForMultipleObjects(2, waitHandles, FALSE, waitTimeoutMs))
				{
					case WAIT_OBJECT_0:
						ReadProcessOutput();
						if (! GetExitCodeProcess(procInfo.hProcess, &processExitCode))
						{
							Log("Command exited, but return code could not be determined", GetLastError());
						}
						else
						{
							sprintf(msg, "Command exited with code %lu", processExitCode);
							Log(msg, 0);
						}
						processState = 0;
						break;
					
					case WAIT_TIMEOUT:
						break;
					
					case WAIT_FAILED:
						Log("MsgWaitForMultipleObjects() failed", GetLastError());
						processState = 2;
						break;
					
					case (WAIT_OBJECT_0 + 1):
						Log("Service stop was requested", 0);
						processState = 2;
						break;
					
					default:
						Log("Unexpected return from MsgWaitForMultipleObjects()", 0);
						processState = 2;
						break;
				}
				
				ReadProcessOutput();
			}
			
			ReadProcessOutput();
		
			LogSetServiceStatus(SERVICE_STOP_PENDING);
	
			if (processState == 2)
			{	
				if (cmdShutdownSeconds > 0)
				{				
					Log("Requesting command to exit..", 0);
					if (! CloseHandle(procStdin_write)) Log("CloseHandle() failed", GetLastError());

					startTime = time(NULL);
					
					while (processState == 2)
					{
						elapsedSeconds = time(NULL) - startTime;
						if (cmdShutdownSeconds <= elapsedSeconds)
						{
							Log("Timed out waiting for command to complete", 0);		
							KillProcess(procInfo.hProcess);
							processState = 0;
							break;
						}
						else
						{
							waitTimeoutMs = (cmdShutdownSeconds - elapsedSeconds) * 1000;
							if (waitTimeoutMs > pipeFlushMs) waitTimeoutMs = pipeFlushMs;
						}
						
						switch(WaitForMultipleObjects(1, waitHandles, FALSE, waitTimeoutMs))
						{
							case WAIT_OBJECT_0:
								ReadProcessOutput();
								if (! GetExitCodeProcess(procInfo.hProcess, &processExitCode))
								{
									Log("Command exited, but return code could not be determined", GetLastError());
								}
								else
								{
									sprintf(msg, "Command exited with code %lu", processExitCode);
									Log(msg, 0);
								}
								processState = 0;
								break;
							
							case WAIT_TIMEOUT:
								break;
							
							case WAIT_FAILED:
								Log("WaitForMultipleObjects() failed", GetLastError());
								KillProcess(procInfo.hProcess);
								processState = 0;
								break;
										
							default:
								Log("Unexpected return from WaitForMultipleObjects()", 0);
								KillProcess(procInfo.hProcess);
								processState = 0;
								break;
						}
						
						ReadProcessOutput();
					}
				}
				else
				{
					KillProcess(procInfo.hProcess);
					processState = 0;					
				}
			}
			
			ReadProcessOutput();
		}
	}
	
	LogSetServiceStatus(SERVICE_STOPPED);
}

int main(int argc, char** argv)
{
	HMODULE hModule;
	char path[MAX_PATH];
	SC_HANDLE scm;
	char* startArgs;
	SC_HANDLE svc;
	FILE* fp;
	SERVICE_TABLE_ENTRY ServiceTable[2];
	SERVICE_DESCRIPTION svcDesc;
	
	// Options
	int mode = 0; // 1=install, 2=remove
	char* svcName = NULL;
	char* command = NULL;
	char* logfile = NULL;
	char* directory = NULL;
	char* timeout = NULL;
	char* maxLog = NULL;
	char* grace = NULL;
	
	if (GetStdHandle(STD_OUTPUT_HANDLE) > 0) // User called
	{
		if (argc %2 == 0) Usage(); // Must be an odd number of args (flag/value pairs, plus process name)
		
		for (int i = 1; i < argc - 1; i += 2)
		{
			if (strcmp(argv[i], "-i") == 0)
			{
				if (mode != 0) Usage();
				mode = 1;
				svcName = argv[i + 1];
			}
			else if (strcmp(argv[i], "-r") == 0)
			{
				if (mode != 0) Usage();
				mode = 2;
				svcName = argv[i + 1];
			}
			else if (strcmp(argv[i], "-c") == 0)
			{
				if (command) Usage();
				command = argv[i + 1];
			}
			else if (strcmp(argv[i], "-l") == 0)
			{
				if (logfile) Usage();
				logfile = argv[i + 1];
			}
			else if (strcmp(argv[i], "-t") == 0)
			{
				if (timeout) Usage();
				timeout = argv[i + 1];
			}
			else if (strcmp(argv[i], "-g") == 0)
			{
				if (grace) Usage();
				grace = argv[i + 1];
			}
			else if (strcmp(argv[i], "-d") == 0)
			{
				if (directory) Usage();
				directory = argv[i + 1];
			}
			else if (strcmp(argv[i], "-m") == 0)
			{
				if (maxLog) Usage();
				maxLog = argv[i + 1];
			}
			else
			{
				Usage();
			}
		}
		
		// Installation defaults / syntax checks
		if (mode == 0) Usage();
		if (! svcName) Usage();
		if ((mode == 1) && (! command)) Usage();
		if (! logfile) logfile = "";
		if (! timeout) timeout = "0";
		if (! grace) grace = "0";
		if (! directory) directory = "";
		if (! maxLog) maxLog = "0";
		
		if (mode == 1)
		{
			if (! (hModule = GetModuleHandle(NULL))) Barf();			
			
			if (! GetModuleFileName(hModule, path, MAX_PATH)) Barf();

			if (! (scm = OpenSCManager(NULL,NULL,SC_MANAGER_CREATE_SERVICE))) Barf();

			startArgs  = malloc(strlen(path) + strlen(command) + 16 + strlen(logfile) + strlen(timeout) + strlen(maxLog) + strlen(grace) + strlen(directory));

			sprintf(startArgs, "%s \"%s\" \"%s\" %s %s %s \"%s\"", path, command, logfile, timeout, maxLog, grace, directory);
			
			if (! (svc = CreateService(scm, svcName, svcName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
				SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, startArgs, NULL, NULL, NULL, NULL, NULL))) Barf();
	
			svcDesc.lpDescription = malloc(20 + strlen(command));
			sprintf(svcDesc.lpDescription, "Runs command: %s", command);
			
			ChangeServiceConfig2(svc, SERVICE_CONFIG_DESCRIPTION, (LPVOID)&svcDesc); // Don't barf on this, not important
	
			printf("\nCreated service %s\n\n", svcName);
		}
		else
		{
			if (! (scm = OpenSCManager(NULL,NULL,SC_MANAGER_CREATE_SERVICE))) Barf();
			
			if (! (svc = OpenService(scm, svcName, SC_MANAGER_ALL_ACCESS))) Barf();
			
			if (! DeleteService(svc)) Barf();

			printf("\nDeleted service %s\n\n", svcName);
		}

    }
	else // SCM called
	{
		processHandle = GetCurrentProcess();
		
		if (argc > 1) cmdToRun = argv[1];
		if ((argc > 2) && (strlen(argv[2]) > 0)) cmdLog = argv[2];
		if (argc > 3) cmdTimeoutSeconds = atol(argv[3]);
		if (argc > 4) cmdMaxLog = atol(argv[4]);
		if (argc > 5) cmdShutdownSeconds = atol(argv[5]);
		if ((argc > 6) && (strlen(argv[6]) > 0)) cmdDirectory = argv[6];
	
		ServiceTable[0].lpServiceName = "cmdsvc";
		ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION) ServiceMain;
		ServiceTable[1].lpServiceName = NULL;
		ServiceTable[1].lpServiceProc = NULL;
		
		InitializeCriticalSection(&logCS);

		shutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (! shutdownEvent) Log("CreateEvent() failed", GetLastError());
  
		if (! StartServiceCtrlDispatcher(ServiceTable)) Log("StartServiceCtrlDispatcher() failed", GetLastError());
	}
	
	return 0;
}

