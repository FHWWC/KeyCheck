using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Common;
using Keys.Properties;
using ProductDetection;

namespace Keys
{
    /// <summary>
    /// Methods for performing a PIDX check on a Key to get detailed information
    /// </summary>
    public class KeyCheck : KeyBase
    {
        #region Filename Constants
        private const string PidgenxFileName = "PidGenX.dll";
        private const string PkeyConfigFileName = "pkeyconfig.xrm-ms";
        #endregion

        /// <summary>
        /// Obtain a Byte Array Representing PkeyConfig for Microsoft Office PIDX Check from Program
        /// </summary>
        /// <param name="useBuiltIn">Load PkeyConfig from Installed Microsoft Office</param>
        /// <param name="product">Name of Microsoft Office Product to Choose based on selection</param>
        /// <returns>Byte Array Representation of PkeyConfig.xrm-ms</returns>
        public static byte[] GetPkeyConfigOffice(bool useBuiltIn = false, string product = "")
        {
            // Load PkeyConfig from System
            if (useBuiltIn)
            {
                return GetBuiltInPkeyConfigOffice();
            }
            // Choose by Product if Provided
            if (product != string.Empty)
            {
                switch (product)
                {
                    case OfficeVersion.Office14 :
                        return Resources.pkeyconfig_office2010;
                    case OfficeVersion.Office15:
                        return Resources.pkeyconfig_office2013;
                }
            }

            // Get PkeyConfig based on Microsoft Office Edition
            switch(OfficeVersion.GetOfficeNumber())
            {
                case 14:
                    return Resources.pkeyconfig_office2010;
                case 15:
                    return Resources.pkeyconfig_office2013;
                default:
                    throw new ApplicationException("No PkeyConfig Matching this Product!");
            }
        }
        /// <summary>
        /// Obtain a Byte Array Representing PkeyConfig for Microsoft Office PIDX Check from System
        /// </summary>
        /// <returns>Byte Array Representation of PkeyConfig.xrm-ms</returns>
        private static byte[] GetBuiltInPkeyConfigOffice()
        {
            string pkeyconfig = string.Empty;
            string officeArch = Architecture.GetOfficeArch();
            int officeNumber = OfficeVersion.GetOfficeNumber();

            switch (officeNumber)
            {
                case 14 :
                case 15 :
                    switch (officeArch)
                    {
                        case Architecture.X86:
                        {
                            pkeyconfig = Environment.ExpandEnvironmentVariables("%CommonProgramFiles%\\microsoft shared\\OFFICE" + officeNumber + "\\Office Setup Controller\\pkeyconfig-office.xrm-ms");
                            break;
                        }
                        case Architecture.WOW:
                        {
                            pkeyconfig = Environment.ExpandEnvironmentVariables("%CommonProgramFiles(x86)%\\microsoft shared\\OFFICE" + officeNumber + "\\Office Setup Controller\\pkeyconfig-office.xrm-ms");
                            break;
                        }
                        case Architecture.X64:
                        {
                            pkeyconfig = Environment.ExpandEnvironmentVariables("%CommonProgramW6432%\\microsoft shared\\OFFICE" + officeNumber + "\\Office Setup Controller\\pkeyconfig-office.xrm-ms");
                            break;
                        }
                    }
                    break;
                default :
                    throw new ApplicationException("Could not find Built-In PkeyConfig");
            }
            return File.ReadAllBytes(pkeyconfig);
        }

        /// <summary>
        /// Obtain a Byte Array Representing PkeyConfig for Microsoft Windows PIDX Check from Program
        /// </summary>
        /// <param name="useBuiltIn">Load PkeyConfig from Installed Microsoft Windows</param>
        /// <param name="product">Name of Microsoft Windows Product to Choose based on selection</param>
        /// <returns>Byte Array Representation of PkeyConfig.xrm-ms</returns>
        public static byte[] GetPkeyConfigWindows(bool useBuiltIn = false, string product = "")
        {
            // Load PkeyConfig from System
            if (useBuiltIn)
            {
                return GetBuiltInPkeyConfigWindows();
            }
            // Choose by Product if Provided
            if (product != string.Empty)
            {
                switch (product)
                {
                    case OSVersion.WinVista:
                    case OSVersion.WinServer2008:
                        return Resources.pkeyconfig_winvista;
                    case OSVersion.Win7:
                    case OSVersion.WinServer2008R2:
                        return Resources.pkeyconfig_win7;
                    case OSVersion.Win7ThinPC:
                        return Resources.pkeyconfig_win7thinpc;
                    case OSVersion.Win7EmbeddedPOS:
                        return Resources.pkeyconfig_win7embeddedpos;
                    case OSVersion.Win7EmbeddedStandard:
                        return Resources.pkeyconfig_win7embeddedstd;
                    case OSVersion.Win8:
                    case OSVersion.WinServer2012:
                        return Resources.pkeyconfig_win8;
                }
            }

            // Get PkeyConfig based on Microsoft Windows Edition
            switch (OSVersion.GetWindowsName())
            {
                case OSVersion.WinVista:
                case OSVersion.WinServer2008:
                    return Resources.pkeyconfig_winvista;
                case OSVersion.Win7:
                case OSVersion.WinServer2008R2:
                    return Resources.pkeyconfig_win7;
                case OSVersion.Win7ThinPC:
                    return Resources.pkeyconfig_win7thinpc;
                case OSVersion.Win7EmbeddedPOS:
                    return Resources.pkeyconfig_win7embeddedpos;
                case OSVersion.Win7EmbeddedStandard:
                    return Resources.pkeyconfig_win7embeddedstd;
                case OSVersion.Win8:
                case OSVersion.WinServer2012:
                    return Resources.pkeyconfig_win8;
                default :
                    throw new ApplicationException("No PkeyConfig Matching this Product!");
            }
        }
        /// <summary>
        /// Obtain a Byte Array Representing PkeyConfig for Microsoft Windows PIDX Check from System
        /// </summary>
        /// <returns>Byte Array Representation of PkeyConfig.xrm-ms</returns>
        private static byte[] GetBuiltInPkeyConfigWindows()
        {
            if (File.Exists(Environment.GetEnvironmentVariable("windir") + @"\System32\spp\tokens\pkeyconfig\pkeyconfig.xrm-ms"))
            {
                return File.ReadAllBytes(Environment.GetEnvironmentVariable("windir") + @"\System32\spp\tokens\pkeyconfig\pkeyconfig.xrm-ms");
            }
            throw new ApplicationException("Could not find Built-In PkeyConfig");
        }

        /// <summary>
        /// Gets the Product Description
        /// </summary>
        /// <param name="pkey">Path to PkeyConfig.xrm-ms file</param>
        /// <param name="aid">Activation ID</param>
        /// <param name="edi">Edition ID</param>
        /// <returns>Product Description</returns>
        private static string GetProductDescription(string pkey, string aid, string edi)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(pkey);
            using (MemoryStream stream = new MemoryStream(Convert.FromBase64String(doc.GetElementsByTagName("tm:infoBin")[0].InnerText)))
            {
                doc.Load(stream);
                XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
                ns.AddNamespace("pkc", "http://www.microsoft.com/DRM/PKEY/Configuration/2.0");
                try
                {
                    XmlNode node = doc.SelectSingleNode("/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='" + aid + "']", ns);
                    if (node == null)
                    {
                        node = doc.SelectSingleNode("/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='" + aid.ToUpper() + "']", ns);
                    }
                    if (node != null && node.HasChildNodes)
                    {
                        if (node.ChildNodes[2].InnerText.Contains(edi))
                        {
                            return node.ChildNodes[3].InnerText;
                        }
                        return "Not Found";
                    }
                    return "Not Found";
                }
                catch (Exception)
                {
                    return "Not Found";
                }
            }
        }
        /// <summary>
        /// Helper Function to Convert Byte Array into a String
        /// </summary>
        /// <param name="bytes">Byte Array to Convert to String</param>
        /// <param name="index">How Many Bytes in the Array to include</param>
        /// <returns>String Conversion of Bytes</returns>
        private static string GetString(byte[] bytes, int index)
        {
            int n = index;
            while (!(bytes[n] == 0 && bytes[n + 1] == 0)) n++;
            return Encoding.ASCII.GetString(bytes, index, n - index).Replace("\0", string.Empty);
        }
        /// <summary>
        /// Run a PIDX Check on a Microsoft Product Key
        /// </summary>
        /// <param name="key">Microsoft Product Key</param>
        /// <param name="pkeyconfig">Byte Array of a PkeyConfig.xrm-ms</param>
        /// <returns>String Representation of a PIDX Check Report</returns>
        public static string CheckKey(string key, byte[] pkeyconfig)
        {
            try
            {
                // Create PIDGENX DLL File
                if (File.Exists(Environment.GetEnvironmentVariable("temp") + "\\" + PidgenxFileName) == false)
                {
                    CommonUtilities.FileCreate(PidgenxFileName, Resources.pidgenx, Environment.GetEnvironmentVariable("temp"));
                }
                // Create PkeyConfig.xrm-ms File
                CommonUtilities.FileCreate(PkeyConfigFileName, pkeyconfig, Environment.GetEnvironmentVariable("temp"));

                // Set Path to Files
                string dllPath = Environment.GetEnvironmentVariable("temp") + "\\" + PidgenxFileName;
                string pKeyPath = Environment.GetEnvironmentVariable("temp") + "\\" + PkeyConfigFileName;

                // Do PIDX Check
                IntPtr dllHandle = NativeMethods.LoadLibrary(dllPath);

                byte[] gpid = new byte[0x32];
                byte[] opid = new byte[0xA4];
                byte[] npid = new byte[0x04F8];

                IntPtr pid = Marshal.AllocHGlobal(0x32);
                IntPtr dpid = Marshal.AllocHGlobal(0xA4);
                IntPtr dpid4 = Marshal.AllocHGlobal(0x04F8);

                const string mspid = "XXXXX";

                gpid[0] = 0x32;
                opid[0] = 0xA4;
                npid[0] = 0xF8;
                npid[1] = 0x04;

                Marshal.Copy(gpid, 0, pid, 0x32);
                Marshal.Copy(opid, 0, dpid, 0xA4);
                Marshal.Copy(npid, 0, dpid4, 0x04F8);

                int retID = NativeMethods.PidGenX(key, pKeyPath, mspid, 0, pid, dpid, dpid4);

                using (StringWriter output = new StringWriter()) 
                {
                    switch (retID)
                    {
                        case 0:
                        {
                            Marshal.Copy(pid, gpid, 0, gpid.Length);
                            Marshal.Copy(dpid4, npid, 0, npid.Length);
                            string keypid = GetString(gpid, 0x0000);
                            string eid = GetString(npid, 0x0008);
                            string aid = GetString(npid, 0x0088);
                            string edi = GetString(npid, 0x0118);
                            string sub = GetString(npid, 0x0378);
                            string lit = GetString(npid, 0x03F8);
                            string lic = GetString(npid, 0x0478);
                            // Fix for 4/5 digit Win 8 CryptoId, Win 7 (3 digit) and Office (2 or 3 digit) are prefixed with zeros which are stripped below
                            string cid = Convert.ToInt32(eid.Substring(6, 5)).ToString(CultureInfo.InvariantCulture);
                            string prd = GetProductDescription(pKeyPath, "{" + aid + "}", edi);

                            output.WriteLine("Product Key: " + key);
                            output.WriteLine("Validity: Valid");
                            output.WriteLine("Product ID: " + keypid);
                            output.WriteLine("Advanced PID: " + eid);
                            output.WriteLine("Activation ID: " + aid);
                            output.WriteLine("Product Description: " + prd);
                            output.WriteLine("Edition Type: " + edi);
                            output.WriteLine("Edition ID: " + sub);
                            output.WriteLine("Key Type: " + lit);
                            output.WriteLine("Eula: " + lic);
                            output.Write("Crypto ID: " + cid);
                            if (lit.ToUpper().Contains("MAK"))
                            {
                                try
                                {
                                    string remainingUses = GetRemainingActivations(eid);
                                    output.WriteLine();
                                    output.Write("Remaining Activation Count: " + remainingUses);
                                }
                                catch (Exception ex)
                                {
                                    output.WriteLine();
                                    output.Write("Remaining Activation Count: Couldn't determine due to error: " + ex.Message);
                                }
                            }

                        }
                            break;
                        case -2147024809:
                            output.WriteLine("Invalid Arguments");
                            break;
                        case -1979645695:
                            output.WriteLine("Invalid Key");
                            break;
                        case -2147024894:
                            output.WriteLine("pkeyconfig.xrm-ms file is not found");
                            break;
                        default:
                            output.WriteLine("Invalid input!!!");
                            break;
                    }
                    Marshal.FreeHGlobal(pid);
                    Marshal.FreeHGlobal(dpid);
                    Marshal.FreeHGlobal(dpid4);

                    NativeMethods.FreeLibrary(dllHandle);

                    // Delete PkeyConfig
                    CommonUtilities.FileDelete(pKeyPath);

                    return output.ToString().Trim();
                }
            }
            catch (Exception ex)
            {
                return "<Key Check Failed>" + Environment.NewLine + ex.Message;
            }
        }
        /// <summary>
        /// Get Remaining Activation Count for a MAK Product Key
        /// </summary>
        /// <param name="pid">Extended PID of the Key</param>
        /// <returns>Number of Activations and whether or not the Key is blocked from further Activation</returns>
        public static string GetRemainingActivations(string pid)
        {
            // Microsoft's PRIVATE KEY for HMAC-SHA256 encoding
            byte[] bPrivateKey = new byte[] 
            { 
                0xfe, 0x31, 0x98, 0x75, 0xfb, 0x48, 0x84, 0x86, 0x9c, 0xf3, 0xf1, 0xce, 0x99, 0xa8, 0x90, 0x64, 
                0xab, 0x57, 0x1f, 0xca, 0x47, 0x04, 0x50, 0x58, 0x30, 0x24, 0xe2, 0x14, 0x62, 0x87, 0x79, 0xa0
            };

            // XML Namespace
            const string uri = "http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0";

            // Create new XML Document
            XmlDocument xmlDoc = new XmlDocument();

            // Create Root Element
            XmlElement rootElement = xmlDoc.CreateElement("ActivationRequest", uri);
            xmlDoc.AppendChild(rootElement);

            // Create VersionNumber Element
            XmlElement versionNumber = xmlDoc.CreateElement("VersionNumber", rootElement.NamespaceURI);
            versionNumber.InnerText = "2.0";
            rootElement.AppendChild(versionNumber);

            // Create RequestType Element
            XmlElement requestType = xmlDoc.CreateElement("RequestType", rootElement.NamespaceURI);
            requestType.InnerText = "2";
            rootElement.AppendChild(requestType);

            // Create Requests Group Element
            XmlElement requestsGroupElement = xmlDoc.CreateElement("Requests", rootElement.NamespaceURI);

            // Create Request Element
            XmlElement requestElement = xmlDoc.CreateElement("Request", requestsGroupElement.NamespaceURI);

            // Add PID as Request Element
            XmlElement pidEntry = xmlDoc.CreateElement("PID", requestElement.NamespaceURI);
            pidEntry.InnerText = pid.Replace("XXXXX", "55041");
            requestElement.AppendChild(pidEntry);

            // Add Request Element to Requests Group Element
            requestsGroupElement.AppendChild(requestElement);

            // Add Requests and Request to XML Document
            rootElement.AppendChild(requestsGroupElement);

            // Get Unicode Byte Array of XML Document
            byte[] byteXml = Encoding.Unicode.GetBytes(xmlDoc.InnerXml);

            // Convert Byte Array to Base64
            string base64Xml = Convert.ToBase64String(byteXml);

            // Compute Digest of the Base 64 XML Bytes
            string digest;
            using (HMACSHA256 hmacsha256 = new HMACSHA256 {Key = bPrivateKey})
            {
                digest = Convert.ToBase64String(hmacsha256.ComputeHash(byteXml));
            }

            // Create SOAP Envelope for Web Request
            string form = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body><BatchActivate xmlns=\"http://www.microsoft.com/BatchActivationService\"><request><Digest>REPLACEME1</Digest><RequestXml>REPLACEME2</RequestXml></request></BatchActivate></soap:Body></soap:Envelope>";
            form = form.Replace("REPLACEME1", digest);      // Put your Digest value (BASE64 encoded)
            form = form.Replace("REPLACEME2", base64Xml);   // Put your Base64 XML value (BASE64 encoded)
            XmlDocument soapEnvelopeXml = new XmlDocument();
            soapEnvelopeXml.LoadXml(form);

            // Create Web Request
            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create("https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx");
            webRequest.Method = "POST";
            webRequest.ContentType = "text/xml; charset=\"utf-8\"";
            webRequest.Headers.Add("SOAPAction", "http://www.microsoft.com/BatchActivationService/BatchActivate");

            // Insert SOAP Envelope into Web Request
            using (Stream stream = webRequest.GetRequestStream())
            {
                soapEnvelopeXml.Save(stream);
            }

            // Begin Async call to Web Request
            IAsyncResult asyncResult = webRequest.BeginGetResponse(null, null);

            // Suspend Thread until call is complete
            asyncResult.AsyncWaitHandle.WaitOne();

            // Get the Response from the completed Web Request
            string soapResult;
            using (WebResponse webResponse = webRequest.EndGetResponse(asyncResult))

            // ReSharper disable AssignNullToNotNullAttribute
            using (StreamReader rd = new StreamReader(webResponse.GetResponseStream()))
            // ReSharper restore AssignNullToNotNullAttribute
            {
                soapResult = rd.ReadToEnd();
            }

            // Parse the ResponseXML from the Response
            using (XmlReader soapReader = XmlReader.Create(new StringReader(soapResult)))
            {
                // Read ResponseXML Value
                soapReader.ReadToFollowing("ResponseXml");
                string responseXml = soapReader.ReadElementContentAsString();

                // Remove HTML Entities from ResponseXML
                responseXml = responseXml.Replace("&gt;", ">");
                responseXml = responseXml.Replace("&lt;", "<");

                // Change Encoding Value in ResponseXML
                responseXml = responseXml.Replace("utf-16", "utf-8");

                // Read Fixed ResponseXML Value as XML
                using (XmlReader reader = XmlReader.Create(new StringReader(responseXml)))
                {
                    reader.ReadToFollowing("ActivationRemaining");
                    string count = reader.ReadElementContentAsString();

                    if (Convert.ToInt32(count) < 0)
                    {
                        reader.ReadToFollowing("ErrorCode");
                        string error = reader.ReadElementContentAsString();

                        if (error == "0x67")
                        {
                            return "0 (Blocked)";
                        }
                    }
                    return count;
                }
            }
        }
    }
}