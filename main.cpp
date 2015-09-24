#ifdef _M_X64
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif // _M_X64

#include <windows.h>

#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <vector>
using namespace std;

/////////////////////////////////////////////////////////////////////////////////////////////////
void CreateMiProcess(char ** begin, char ** end)
{
  std::string cmdLine;
  for (char **it = begin; it != end; ++it)
  {
    if (!cmdLine.empty()) cmdLine += ' ';

    if (strchr(*it, ' '))
    {
      cmdLine += '"';
      cmdLine += *it;
      cmdLine += '"';
    }
    else
    {
      cmdLine += *it;
    }
  }


  STARTUPINFO startupInfo = { sizeof( startupInfo ) };
  startupInfo.dwFlags = STARTF_USESHOWWINDOW;
  startupInfo.wShowWindow = SW_SHOWNORMAL; // Assist GUI programs
  PROCESS_INFORMATION ProcessInformation = {0};

  if ( ! CreateProcess(0, const_cast<char*>(cmdLine.c_str()),
     0, 0, true,
     DEBUG_ONLY_THIS_PROCESS,
     0, 0, &startupInfo, &ProcessInformation) )
  {
    std::ostringstream oss;
    oss << GetLastError();
    throw std::runtime_error(std::string("Unable to start ") + *begin + ": " + oss.str());
  }

  CloseHandle( ProcessInformation.hProcess );
  CloseHandle( ProcessInformation.hThread );

}
//////////////////////////////////////////////////////////////////////////////
  // Helper function to read up to maxSize bytes from address in target process
  // into the supplied buffer.
  // Returns number of bytes actually read.
  SIZE_T ReadPartialProcessMemory(HANDLE hProcess, LPCVOID address, LPVOID buffer, SIZE_T minSize, SIZE_T maxSize)
  {
    SIZE_T length = maxSize;
    while (length >= minSize)
    {
      if ( ReadProcessMemory(hProcess, address, buffer, length, 0) )
      {
        return length;
      }
      length--;

      static SYSTEM_INFO SystemInfo;
      static BOOL b = (GetSystemInfo(&SystemInfo), TRUE);

      SIZE_T pageOffset = ((ULONG_PTR)address + length) % SystemInfo.dwPageSize;
      if (pageOffset > length)
        break;
      length -= pageOffset;
    }
    return 0;
  }

  ////////////////////////////////////////////////////////
std::string getString(HANDLE hProcess,PVOID address, BOOL unicode, DWORD maxStringLength){

if (unicode)
  {
    std::vector<wchar_t> chVector(maxStringLength + 1);
    ReadPartialProcessMemory(hProcess, address, &chVector[0], sizeof(wchar_t), maxStringLength * sizeof(wchar_t));
    size_t const wcLen = wcstombs(0, &chVector[0], 0);
    if (wcLen == (size_t)-1)
    {
       return "invalid string";
    }
    else
    {
       std::vector<char> mbStr(wcLen + 1);
       wcstombs(&mbStr[0], &chVector[0], wcLen);
       return &mbStr[0];
    }
  }
  else
  {
    std::vector<char> chVector(maxStringLength + 1);
    ReadPartialProcessMemory(hProcess, address, &chVector[0], 1, maxStringLength);
    return &chVector[0];
  }
  }
///////////////////////////////////////////////////////////////////

int main( int argc, char **argv )
{
  if ( argc <= 1 )
  {
    printf( "Syntax: ProcessTracer command_line\n" );
    return 1;
  }
  ++argv;
  --argc;
	// Get token for this process
	HANDLE token;
	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) == false)
	{
		printf("OpenProcessToken Failed: 0x%X\n", GetLastError());
		exit(-1);
	}

	//Get LUID for debug privilege}
	TOKEN_PRIVILEGES tkp;
	if(LookupPrivilegeValue(NULL, "SeDebugPrivilege", &tkp.Privileges[0].Luid) == false)
	{
		printf("LookupPrivilegeValue failed: 0x%X\n", GetLastError());
		exit(-1);
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if(AdjustTokenPrivileges(token, false, &tkp, 0, NULL, NULL) == false)
	{
		printf("AdjustTokenPrivileges Failed: 0x%X\n", GetLastError());
		exit(-1);
	}

	HANDLE hProc = INVALID_HANDLE_VALUE;
  // Use the normal heap manager
  _putenv("_NO_DEBUG_HEAP=1");

  try
  {
    CreateMiProcess(argv, argv + argc);
    //ProcessTracer().run();
  }
  catch ( std::exception &ex)
  {
    std::cerr << "Unexpected exception: " << ex.what() << std::endl;
    return 1;
  }
  DEBUG_EVENT deDebugger;
	DWORD dwContinueState;
	bool bFirstTime = true;  // needed for the exception handling on DAP
	while(WaitForDebugEvent(&deDebugger, INFINITE) != 0)
	{
		dwContinueState = DBG_CONTINUE;
		switch(deDebugger.dwDebugEventCode)
		{
			case EXCEPTION_DEBUG_EVENT: {


				printf("EXCEPTION_DEBUG_EVENT: First Chance = %d\n", deDebugger.u.Exception.dwFirstChance);
				if(bFirstTime = true)
					bFirstTime = false;
					#ifdef _M_X64
			          else if (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_WX86_BREAKPOINT)
                                {
                                            std::cout << "WOW64 initialised" << std::endl;
                      }
                    #endif // _M_X64
				else
					dwContinueState = DBG_EXCEPTION_NOT_HANDLED;   // use this to allow process to handle exception
				break;
			}
			case CREATE_THREAD_DEBUG_EVENT: {
				printf("CREATE_THREAD_DEBUG_EVENT: %d\n", deDebugger.u.CreateThread.hThread);
				break;
			}
			case CREATE_PROCESS_DEBUG_EVENT: {
			    hProc=deDebugger.u.CreateProcessInfo.hProcess;
			    std::cout << "CREATE PROCESS " << deDebugger.dwProcessId  << std::endl;
				//printf("CREATE_PROCESS_DEBUG_EVENT\n");
				break;
			}
			case EXIT_THREAD_DEBUG_EVENT: {
				printf("EXIT_THREAD_DEBUG_EVENT: %d\n", deDebugger.u.ExitThread.dwExitCode);
				break;
			}
			case EXIT_PROCESS_DEBUG_EVENT: {
				printf("EXIT_PROCESS_DEBUG_EVENT: %d\n", deDebugger.u.ExitProcess.dwExitCode);
				exit(0);
				break;
			}
			case LOAD_DLL_DEBUG_EVENT: {
			    void *pString = 0;
			    ReadProcessMemory(hProc, deDebugger.u.LoadDll.lpImageName, &pString, sizeof(pString), 0);
			    //cout << pString << "\n"; //Display it
                std::string const fileName(getString(hProc,pString, deDebugger.u.LoadDll.fUnicode, MAX_PATH) );

			    std::cout << "LOAD_DLL_DEBUG_EVENT: " << deDebugger.u.LoadDll.lpBaseOfDll << " "  << fileName << std::endl;
				//printf("LOAD_DLL_DEBUG_EVENT\n");
				break;
			}
			case UNLOAD_DLL_DEBUG_EVENT: {
			    std::cout << "UNLOAD_DLL_DEBUG_EVENT: " << deDebugger.u.UnloadDll.lpBaseOfDll << std::endl;
				//printf("UNLOAD_DLL_DEBUG_EVENT\n");
				break;
			}
			case OUTPUT_DEBUG_STRING_EVENT: {
				char *aBuf = new char[deDebugger.u.DebugString.nDebugStringLength];
				DWORD dwRead;
				ReadProcessMemory(hProc, deDebugger.u.DebugString.lpDebugStringData, aBuf, deDebugger.u.DebugString.nDebugStringLength, &dwRead);
				printf("%s", aBuf);
				delete aBuf;
				break;
			}
			case RIP_EVENT: {
				printf("Got a RIP_EVENT!\n");
				break;
			}
		}
		ContinueDebugEvent(deDebugger.dwProcessId, deDebugger.dwThreadId, dwContinueState);
	}
	exit(0);
	return 0;

  return 0;
}
