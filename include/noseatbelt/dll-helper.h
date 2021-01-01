#pragma once

#ifdef WIN32
#define DllExport   __declspec( dllexport )
#define DllImport   __declspec( dllimport )
#else
#define DllExport /* Only on WIN32 */
#define DllImport /* Only on WIN32 */
#endif