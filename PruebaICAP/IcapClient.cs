using System.IO;
using System;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.IO.Pipes;
using System.Net.Http.Headers;

namespace PruebaICAP
{
    public class IcapClient : IDisposable
    {
        private const string USERAGENT = "IT-Kartellet ICAP Client/1.1";
        private const string ICAPTERMINATOR = "\r\n\r\n";
        private const string HTTPTERMINATOR = "0\r\n\r\n";
        readonly string server;
        private readonly int stdRecieveLength = 8192;
        private readonly int stdSendLength = 8192;
        private readonly Socket sender;
        private readonly int stdPreviewSize;

        public IcapClient(string serverIp) 
        { 
            this.server = serverIp;
            sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            sender.Connect(server, 1344); 
            var result = GetOptions();
            var keys = ParseHeader(result);
            if (!keys.ContainsKey("Preview") || !int.TryParse(keys["Preview"], out stdPreviewSize)) { throw new IcapException("Not preview size"); }
        }

        public bool Scan(string file)
        {
            using var fileStream = new FileStream(file, FileMode.Open);
            var buffer = new byte[fileStream.Length];
            fileStream.Read(buffer, 0, buffer.Length);
            return Scan(buffer);
        }

        public bool Scan(byte[] data)
        {
            int fileSize = data.Length;
            using var fileStream = new MemoryStream(data);
            //First part of header
            string resBody = $"Content-Length: {fileSize}\r\n\r\n";

            int previewSize = stdPreviewSize;
            if (fileSize < stdPreviewSize)
            {
                previewSize = fileSize;
            }

            byte[] requestBuffer = Encoding.ASCII.GetBytes(
                $"RESPMOD icap://{server}/avscan ICAP/1.0\r\n"
                + $"Host: {server}\r\n"
                + "User-Agent: " + USERAGENT + "\r\n"
                + "Allow: 204\r\n"
                + "Preview: " + previewSize + "\r\n"
                + "Encapsulated: res-hdr=0, res-body=" + resBody.Length + "\r\n"
                + "\r\n"
                + resBody
                + previewSize.ToString("X") + "\r\n");

            sender.Send(requestBuffer);
            byte[] chunk = new byte[previewSize];
            fileStream.Read(chunk, 0, previewSize);
            sender.Send(chunk);
            sender.Send(Encoding.ASCII.GetBytes("\r\n"));

            if (fileSize <= previewSize)
            {
                sender.Send(Encoding.ASCII.GetBytes("0; ieof\r\n\r\n"));
            }
            else if (previewSize != 0)
            {
                sender.Send(Encoding.ASCII.GetBytes("0\r\n\r\n"));
            }
            Dictionary<string, string> responseMap;
            int status;
            string tempString = string.Empty;
            if (fileSize > previewSize)
            {
                //TODO: add timeout. It will hang if no response is recieved
                String parseMe = GetHeader(ICAPTERMINATOR);
                responseMap = ParseHeader(parseMe);
                
                responseMap.TryGetValue("StatusCode", out tempString);
                if (tempString != null)
                {
                    _ = int.TryParse(tempString, out status);

                    switch (status)
                    {
                        case 100: break; //Continue transfer
                        case 200: return false;
                        case 204: return true;
                        case 404: throw new IcapException("404: ICAP Service not found");
                        default: throw new IcapException("Server returned unknown status code:" + status);
                    }
                }
            }
            //Sending remaining part of file
            if (fileSize > previewSize)
            {
                int offset = previewSize;
                int n;
                byte[] buffer = new byte[stdSendLength];
                while ((n = fileStream.Read(buffer, 0, stdSendLength)) > 0)
                {
                    offset += n;  // offset for next reading
                    sender.Send(Encoding.ASCII.GetBytes(n.ToString("X") + "\r\n"));
                    sender.Send(buffer, n, SocketFlags.None);
                    sender.Send(Encoding.ASCII.GetBytes("\r\n"));
                }
                //Closing file transfer.
                sender.Send(Encoding.ASCII.GetBytes("0\r\n\r\n"));
            }

            responseMap = ParseHeader(GetHeader(ICAPTERMINATOR));

            responseMap.TryGetValue("status", out tempString);
            if (tempString != null)
            {
                int.TryParse(tempString, out status);


                if (status == 204) { return true; } //Unmodified

                if (status == 200) //OK - The ICAP status is ok, but the encapsulated HTTP status will likely be different
                {
                    var response = GetHeader(HTTPTERMINATOR);
                    // Searching for: <title>ProxyAV: Access Denied</title>
                    int x = response.IndexOf("<title>", 0);
                    int y = response.IndexOf("</title>", x);
                    String statusCode = response.Substring(x + 7, y - x - 7);

                    if (statusCode.Equals("ProxyAV: Access Denied"))
                    {
                        return false;
                    }
                }
            }
            throw new IcapException("Unrecognized or no status code in response header.");
        }

        private static Dictionary<string, string> ParseHeader(string response)
        {
            var lineas = response.Split("\r\n");
            var status = new Regex("ICAP/1\\.0 (\\d\\d\\d) \\w+");
            var stMatch = status.Match(lineas[0]);
            if (!stMatch.Success) { throw new IcapException("Not status receive"); }
            var result = new Dictionary<string, string>
            {
                { "status", stMatch.Groups[1].Value }
            };
            var keyReg = new Regex("^(\\w+):\\s+(.+)$");
            foreach (var line in lineas.Skip(1)) 
            { 
                var match = keyReg.Match(line);
                if(!match.Success) continue;
                result.Add(match.Groups[1].Value, match.Groups[2].Value);
            }
            return result;

        }

        private string GetOptions()
        {
            byte[] msg = Encoding.ASCII.GetBytes(
                "OPTIONS icap://" + server + "/avscan ICAP/1.0\r\n"
                + "Host: " + server + "\r\n"
                + "User-Agent: " + USERAGENT + "\r\n"
                + "Encapsulated: null-body=0\r\n"
                + "\r\n");
            sender.Send(msg);

            return GetHeader(ICAPTERMINATOR);
        }

        private string GetHeader(string terminator)
        {
            byte[] endofheader = Encoding.UTF8.GetBytes(terminator);
            byte[] buffer = new byte[stdRecieveLength];

            int n;
            int offset = 0;
            //stdRecieveLength-offset is replaced by '1' to not receive the next (HTTP) header.
            while ((offset < stdRecieveLength) && ((n = sender.Receive(buffer, offset, 1, SocketFlags.None)) != 0)) // first part is to secure against DOS
            {
                offset += n;
                if (offset > endofheader.Length + 13) // 13 is the smallest possible message (ICAP/1.0 xxx\r\n) or (HTTP/1.0 xxx\r\n)
                {
                    byte[] lastBytes = new byte[endofheader.Length];
                    Array.Copy(buffer, offset - endofheader.Length, lastBytes, 0, endofheader.Length);
                    if (endofheader.SequenceEqual(lastBytes))
                    {
                        return Encoding.ASCII.GetString(buffer, 0, offset);
                    }
                }
            }
            throw new IcapException("Error in getHeader() method");
        }

        public void Dispose()
        {
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
            sender.Dispose();
        }
    }
}
