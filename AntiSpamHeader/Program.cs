using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiSpamHeader
{
    class Program
    {
        public static List<ViewAntiSpamFilter> ListAntiSpam { get; set; }

        static void Main(string[] args)
        {
            string headerValue = ReadFileHeaderValue();

            //ListAntiSpam = new List<ViewAntiSpamFilter>();

            //ProcessSpfHeaderValue(headerValue);
            //ProcessDkimHeaderValue(headerValue);
            ProcessSclHeaderValue(headerValue);

            Console.Read();
        }

        private static void ProcessSpfHeaderValue(string headerValue)
        {
            //Search and Read SPF.
            var spfIndex = headerValue.IndexOf("spf=");

            Console.WriteLine("--------------------------------");

            Console.WriteLine(spfIndex);

            var spfValue = headerValue.Substring(spfIndex, 9);

            Console.WriteLine("--------------------------------");

            Console.WriteLine(spfValue);

            var item = new ViewAntiSpamFilter();

            switch (spfValue.Replace(" ", string.Empty))
            {
                case "spf=pass":
                    item.Description = "A record exists and the IP is approved for sending email.";
                    item.Name = "Spf";
                    item.Result = "success";
                    break;
                case "spf=neutr":
                    item.Description = "A record does not exist and is neither permitted nor denied.";
                    item.Name = "Spf";
                    item.Result = "warning";
                    break;
                case "spf=softf":
                    item.Description = "A record exists and the IP is not approved for sending email, but the record states to accept the messages anyways.";
                    item.Name = "Spf";
                    item.Result = "danger";
                    break;
                case "spf=fail":
                    item.Description = "A record exists and the IP is not approved for sending email.";
                    item.Name = "Spf";
                    item.Result = "danger";
                    break;
                default:
                    break;
            }

            ListAntiSpam.Add(item);

        }

        private static void ProcessDkimHeaderValue(string headerValue)
        {
            //Search and Read SPF.
            var spfIndex = headerValue.IndexOf("dkim=");

            Console.WriteLine("--------------------------------");

            Console.WriteLine(spfIndex);

            var dkimValue = headerValue.Substring(spfIndex, 10);

            Console.WriteLine("--------------------------------");

            Console.WriteLine(dkimValue);

            var item = new ViewAntiSpamFilter();

            switch (dkimValue.Replace(" ", string.Empty))
            {
                case "dkim=pass":
                    item.Description = "A record exists and the IP is approved for sending email.";
                    item.Name = "Dkim";
                    item.Result = "success";
                    break;
                case "dkim=fail":
                    item.Description = "A record does not exist and is neither permitted nor denied.";
                    item.Name = "Dkim";
                    item.Result = "warning";
                    break;
                case "dkim=none":
                    item.Description = "A record exists and the IP is not approved for sending email, but the record states to accept the messages anyways.";
                    item.Name = "Dkim";
                    item.Result = "danger";
                    break;
                case "dkim=polic":
                    item.Description = "A record exists and the IP is not approved for sending email, but the record states to accept the messages anyways.";
                    item.Name = "Dkim";
                    item.Result = "danger";
                    break;
                case "dkim=neutr":
                    item.Description = "A record exists and the IP is not approved for sending email, but the record states to accept the messages anyways.";
                    item.Name = "Dkim";
                    item.Result = "danger";
                    break;
                case "dkim=tempe":
                    item.Description = "A record exists and the IP is not approved for sending email, but the record states to accept the messages anyways.";
                    item.Name = "Dkim";
                    item.Result = "danger";
                    break;
                case "dkim=perme":
                    item.Description = "A record exists and the IP is not approved for sending email, but the record states to accept the messages anyways.";
                    item.Name = "Dkim";
                    item.Result = "danger";
                    break;
                default:
                    break;
            }

            ListAntiSpam.Add(item);

        }

        private static void ProcessSclHeaderValue(string headerValue)
        {
            var sclKey = "X-MS-Exchange-Organization-SCL:";
            var sclIndex = headerValue.IndexOf(sclKey);

            var sclValue = headerValue.Substring(sclIndex, 34);

            var item = new ViewAntiSpamFilter();

            var value = sclValue.Split(':');
            int resultScl = Convert.ToInt32(value[1]);

            item.Name = "Scl";

            if (resultScl.Equals(-1))
            {
                item.Description = "The message bypassed antispam scanning(for example, the message was from an internal sender).";
                item.Result = "success";
            }else if (resultScl <= 5)
            {
                item.Description = "The message bypassed antispam scanning(for example, the message was from an internal sender).";
                item.Result = "warning";
            }else if (resultScl > 5)
            {
                item.Description = "The message bypassed antispam scanning(for example, the message was from an internal sender).";
                item.Result = "warning";
            }

            
        }

        private static string ReadFileHeaderValue()
        {
            var result = File.ReadAllText(@"D:\Projects\Poc's\Net\AntiSpamHeader\header.txt");

            Console.WriteLine(result);

            return result;
        }
    }
}
