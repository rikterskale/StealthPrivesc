using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
namespace StealthPrivesc {
    public sealed class SqliteResult {public string[][] Rows; public bool Truncated;}
    public static class NativeSqlite {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Progress(IntPtr context);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_open_v2(byte[] path,out IntPtr db,int flags,IntPtr vfs);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_close(IntPtr db);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_busy_timeout(IntPtr db,int milliseconds);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern void sqlite3_progress_handler(IntPtr db,int instructions,Progress callback,IntPtr context);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_prepare_v2(IntPtr db,byte[] sql,int bytes,out IntPtr statement,IntPtr tail);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_stmt_readonly(IntPtr statement);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_step(IntPtr statement);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_finalize(IntPtr statement);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_column_count(IntPtr statement);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern IntPtr sqlite3_column_text(IntPtr statement,int column);
        [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] static extern int sqlite3_column_bytes(IntPtr statement,int column);
        public static SqliteResult Query(string path,string query,int maximum,int seconds){
            IntPtr db=IntPtr.Zero,statement=IntPtr.Zero;var watch=Stopwatch.StartNew();Progress callback=delegate(IntPtr p){return watch.Elapsed.TotalSeconds>seconds?1:0;};
            try{
                int result=sqlite3_open_v2(Encoding.UTF8.GetBytes(path+"\0"),out db,1,IntPtr.Zero);if(result!=0)throw new InvalidOperationException("SQLite open status "+result);
                sqlite3_busy_timeout(db,1000);sqlite3_progress_handler(db,1000,callback,IntPtr.Zero);
                var sql=Encoding.UTF8.GetBytes(query+"\0");result=sqlite3_prepare_v2(db,sql,sql.Length,out statement,IntPtr.Zero);if(result!=0)throw new InvalidOperationException("SQLite prepare status "+result);
                if(sqlite3_stmt_readonly(statement)!=1)throw new InvalidOperationException("Only read-only statements are allowed.");
                var rows=new List<string[]>();bool truncated=false;
                while((result=sqlite3_step(statement))==100){
                    if(rows.Count>=maximum){truncated=true;break;}
                    int columns=sqlite3_column_count(statement);var row=new string[columns];
                    for(int i=0;i<columns;i++){IntPtr pointer=sqlite3_column_text(statement,i);int length=sqlite3_column_bytes(statement,i);if(length>262144)throw new InvalidOperationException("SQLite field exceeds size limit.");if(pointer!=IntPtr.Zero){var bytes=new byte[length];Marshal.Copy(pointer,bytes,0,length);row[i]=Encoding.UTF8.GetString(bytes);Array.Clear(bytes,0,bytes.Length);}}
                    rows.Add(row);
                }
                if(result!=101 && !truncated)throw new InvalidOperationException("SQLite step status "+result);
                return new SqliteResult{Rows=rows.ToArray(),Truncated=truncated};
            }finally{if(statement!=IntPtr.Zero)sqlite3_finalize(statement);if(db!=IntPtr.Zero){sqlite3_progress_handler(db,0,null,IntPtr.Zero);sqlite3_close(db);}GC.KeepAlive(callback);}
        }
    }
}
