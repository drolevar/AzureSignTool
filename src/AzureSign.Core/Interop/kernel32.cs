using System;
using System.Runtime.InteropServices;

namespace AzureSign.Core.Interop
{
    /// <summary>
    /// Imports from kernel32.dll
    /// </summary>
    public static class kernel32
    {
        /// <summary>
        /// Adds a directory to the process DLL search path.
        /// </summary>
        /// <param name="path">An absolute path to the directory to add to the search path. For example, to add the directory Dir2 to the process DLL search path, specify \Dir2.</param>
        /// <returns>If the function succeeds, the return value is an opaque pointer that can be passed to RemoveDllDirectory to remove the DLL from the process DLL search path.
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.</returns>
        [method: DllImport(nameof(kernel32), CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr AddDllDirectory(
            [param: In] string path
        );
    }
}
