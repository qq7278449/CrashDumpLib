#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <tchar.h>
#include <dbghelp.h>
#include "miniDumper.h"

CMiniDumper *g_miniDumper = NULL;
const int USER_DATA_BUFFER_SIZE = 4096;

typedef BOOL (WINAPI *MINIDUMPWRITEDUMP)(HANDLE hProcess,
                                         DWORD dwPid,
                                         HANDLE hFile,
                                         MINIDUMP_TYPE DumpType,
                                         CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
                                         CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
                                         CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

CMiniDumper::CMiniDumper( bool bPromptUserForMiniDump )
{
	LPTOP_LEVEL_EXCEPTION_FILTER pRet = ::SetUnhandledExceptionFilter( unhandledExceptionHandler );
	if (pRet == NULL)
	{
		printf("SetUnhandledExceptionFilter failed... This program can't get dmp file at crash time\n");
	}
	DisableSetUnhandledExceptionFilter();	//防止CRT篡改
    InitializeCriticalSection( &m_cs );
	g_miniDumper = this;
}

CMiniDumper::~CMiniDumper( void )
{
    DeleteCriticalSection( &m_cs );
}

LONG CMiniDumper::unhandledExceptionHandler( _EXCEPTION_POINTERS *pExceptionInfo )
{
	//int nRet = MessageBox(NULL, "Sorry！软件崩溃了，为了提高软件质量，请点击\"确定\"按钮，生成转储文件，并把转储文件发送给开发人员。感谢您的配合！", "软件一不小心崩溃了...", MB_OKCANCEL);
	//if (nRet == IDCANCEL)
	//{
	//	TerminateProcess(GetCurrentProcess(), -1);
	//}
	g_miniDumper->writeMiniDump( pExceptionInfo );
	TerminateProcess(GetCurrentProcess(), -1);
	return 0;
}

void CMiniDumper::setMiniDumpFileName( void )
{
	SYSTEMTIME st;
	GetLocalTime(&st);

    sprintf( m_szMiniDumpPath,
                 _T( "%s%s.%d-%d-%d-%d-%d-%d.dmp" ),
                 m_szAppPath,
                 m_szAppBaseName,
				 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond );
}

bool CMiniDumper::getImpersonationToken( HANDLE* phToken )
{
    *phToken = NULL;

    if( !OpenThreadToken( GetCurrentThread(),
                          TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                          TRUE,
                          phToken) )
    {
        if( GetLastError() == ERROR_NO_TOKEN )
        {
            if( !OpenProcessToken( GetCurrentProcess(),
                                   TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                   phToken) )
                return false;
        }
        else
            return false;
    }

    return true;
}

BOOL CMiniDumper::enablePrivilege( LPCTSTR pszPriv, HANDLE hToken, TOKEN_PRIVILEGES* ptpOld )
{
    BOOL bOk = FALSE;

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bOk = LookupPrivilegeValue( 0, pszPriv, &tp.Privileges[0].Luid );

    if( bOk )
    {
        DWORD cbOld = sizeof(*ptpOld);
        bOk = AdjustTokenPrivileges( hToken, FALSE, &tp, cbOld, ptpOld, &cbOld );
    }

    return (bOk && (ERROR_NOT_ALL_ASSIGNED != GetLastError()));
}

BOOL CMiniDumper::restorePrivilege( HANDLE hToken, TOKEN_PRIVILEGES* ptpOld )
{
    BOOL bOk = AdjustTokenPrivileges(hToken, FALSE, ptpOld, 0, NULL, NULL);
    return ( bOk && (ERROR_NOT_ALL_ASSIGNED != GetLastError()) );
}


LONG CMiniDumper::writeMiniDump( _EXCEPTION_POINTERS *pExceptionInfo )
{
	LONG retval = EXCEPTION_CONTINUE_SEARCH;
	m_pExceptionInfo = pExceptionInfo;

    HANDLE hImpersonationToken = NULL;
    if( !getImpersonationToken( &hImpersonationToken ) )
        return FALSE;
	
	HMODULE hDll = NULL;
	TCHAR szDbgHelpPath[MAX_PATH];

	if( GetModuleFileName( NULL, m_szAppPath, MAX_PATH ) )
	{
		TCHAR *pSlash = _tcsrchr( m_szAppPath, '\\' );

		if( pSlash )
		{
			_tcscpy_s( m_szAppBaseName, pSlash + 1);
			*(pSlash+1) = 0;
		}

		_tcscpy_s( szDbgHelpPath, m_szAppPath );
        _tcscat_s( szDbgHelpPath, _T("DBGHELP.DLL") );
		hDll = ::LoadLibrary( szDbgHelpPath );
	}

	if( hDll == NULL )
	{
		// If we haven't found it yet - try one more time.
		hDll = ::LoadLibrary( _T("DBGHELP.DLL") );
	}

	LPCTSTR szResult = NULL;

	if( hDll )
	{
		MINIDUMPWRITEDUMP MiniDumpWriteDump = 
            (MINIDUMPWRITEDUMP)::GetProcAddress( hDll, "MiniDumpWriteDump" );

		if( MiniDumpWriteDump != NULL )
        {
			TCHAR szScratch[USER_DATA_BUFFER_SIZE];

			setMiniDumpFileName();

			// Create the mini-dump file...
			HANDLE hFile = ::CreateFile( m_szMiniDumpPath, 
                                            GENERIC_WRITE, 
                                            FILE_SHARE_WRITE, 
                                            NULL, 
                                            CREATE_ALWAYS, 
                                            FILE_ATTRIBUTE_NORMAL, 
                                            NULL );

			if( hFile != INVALID_HANDLE_VALUE )
			{
				_MINIDUMP_EXCEPTION_INFORMATION ExInfo;
				ExInfo.ThreadId          = ::GetCurrentThreadId();
				ExInfo.ExceptionPointers = pExceptionInfo;
				ExInfo.ClientPointers    = NULL;

                // We need the SeDebugPrivilege to be able to run MiniDumpWriteDump
                TOKEN_PRIVILEGES tp;
                BOOL bPrivilegeEnabled = enablePrivilege( SE_DEBUG_NAME, hImpersonationToken, &tp );

                BOOL bOk;

                // DBGHELP.dll is not thread-safe, so we need to restrict access...
                EnterCriticalSection( &m_cs );
                {
					// Write out the mini-dump data to the file...
                    bOk = MiniDumpWriteDump( GetCurrentProcess(),
                                                GetCurrentProcessId(),
                                                hFile,
                                                MiniDumpWithFullMemory,
                                                &ExInfo,
                                                NULL,
                                                NULL );
                }
                LeaveCriticalSection( &m_cs );

                // Restore the privileges when done
                if( bPrivilegeEnabled )
	                restorePrivilege( hImpersonationToken, &tp );

                if( bOk )
				{
					szResult = NULL;
					retval = EXCEPTION_EXECUTE_HANDLER;
				}

				::CloseHandle( hFile );
			}
		}
		else
		{
			szResult = _T( "Call to GetProcAddress failed to find MiniDumpWriteDump. ")
                       _T("The DBGHELP.DLL is possibly outdated." );
		}
	}
	else
	{
		szResult = _T( "Call to LoadLibrary failed to find DBGHELP.DLL." );
	}

	if( szResult )
		::MessageBox( NULL, szResult, NULL, MB_OK );

	TerminateProcess( GetCurrentProcess(), 0 );

	return retval;
}

void CMiniDumper::DisableSetUnhandledExceptionFilter()
{
	void *addr = (void*)GetProcAddress(LoadLibrary(_T("kernel32.dll")),
                                                         "SetUnhandledExceptionFilter");
    if (addr)
    {
		unsigned char code[16];
		int size = 0;

#ifdef _X64
		code[size++] = 0x33;
		code[size++] = 0xC0;
		code[size++] = 0xC3;
#else
		code[size++] = 0x33;
		code[size++] = 0xC0;
		code[size++] = 0xC2;
		code[size++] = 0x04;
		code[size++] = 0x00;
#endif

		DWORD dwOldFlag, dwTempFlag;
		VirtualProtect(addr, size, PAGE_READWRITE, &dwOldFlag);
		WriteProcessMemory(GetCurrentProcess(), addr, code, size, NULL);
		VirtualProtect(addr, size, dwOldFlag, &dwTempFlag);
	}
}