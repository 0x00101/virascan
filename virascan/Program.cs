using System;
using System.Data.SQLite;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace virascan
{
    class Program
    {
        static void Main(string[] args)
        {
            string d_file = "base/malware.sqlite";
            DataTable dTable = new DataTable();

            Console.WriteLine("Virascan (dev-tree) by 0x00101");
            Console.WriteLine("Press any key to start check...");
            Console.ReadKey();


            if (!File.Exists(d_file))
                SQLiteConnection.CreateFile(d_file);

            //var virnames = new IniFile("names.vir");
            

            Console.WriteLine("Starting scan...");


            try
            {
                SQLiteCommand m_sqlCmd = new SQLiteCommand();
                SQLiteConnection m_dbConn = new SQLiteConnection("Data Source=" + d_file + ";Version=3;");
                m_dbConn.Open();
                m_sqlCmd.Connection = m_dbConn;

                m_sqlCmd.CommandText = "CREATE TABLE IF NOT EXISTS VirascanDB (id INTEGER PRIMARY KEY AUTOINCREMENT, hash VARCHAR(40), name VARCHAR(100))";                
                m_sqlCmd.ExecuteNonQuery();

                string sql_ids = "SELECT * FROM id";
                SQLiteDataAdapter adapter = new SQLiteDataAdapter(sql_ids, m_dbConn);
                adapter.Fill(dTable);

                if (dTable.Rows.Count > 0)
                {
                    for (int i = 0; i < dTable.Rows.Count; i++)
                       Console.WriteLine(dTable.Rows[i].ItemArray);
                }
                else
                    Console.WriteLine("sqlite-virascan#: Database is empty");

            }
            catch (SQLiteException ex)
            {
                Console.WriteLine("sqlite-virascan#: Exception:" + ex);
            }

/* string[] arr = Directory.GetFiles(@"E:\OSPanel", "*.*", SearchOption.AllDirectories);
 foreach (var item in arr)
 {

     string filename = item.ToString();
     string filehash = CalculateMD5(filename);

     Console.WriteLine(filename + " : " + filehash);

     for (int i = 1; i <= /*Int32.Parse(virnames.Read("count") 1; i++)
     {
         string virdbhash = virnames.Read("" + i);
         if (virdbhash == filehash)
         {
             Console.WriteLine("aaaargh detected1!!");
             Console.ReadKey();
             Process.GetCurrentProcess().Kill();
         }
     }
 }*/
Console.ReadKey();
         
        }

        static string CalculateMD5(string filename)
        {
            using (FileStream stream = File.OpenRead(filename))
            {
                using (var bufferedStream = new BufferedStream(stream, 8196 * 100))
                {
                    var sha = new MD5CryptoServiceProvider();
                    byte[] checksum = sha.ComputeHash(bufferedStream);
                    return BitConverter.ToString(checksum).Replace("-", String.Empty);
                }
            }
        }
    }
}
