// CrashDump.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "MiniDumper.h"
#include "CrashDump.h"

CMiniDumper* g_miniDumperObject = NULL;

void SetGlobalCrashDump()
{
	if (g_miniDumperObject == NULL)
	{
		g_miniDumperObject = new CMiniDumper(true);
	}
}