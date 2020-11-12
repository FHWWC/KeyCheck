using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;

namespace OEMLibrary
{

    public interface IDotNetInterface
    {
        string version();
        string VerifySlic(string filePath);
        string VerifyCert(string filePath);
        string SlicCertCompare(string filePath1, string filePath2);
        string Hexdump(string slicPath);
    }

    [ClassInterface(ClassInterfaceType.AutoDispatch)]
    //[ClassInterface(ClassInterfaceType.None)]
    //[ClassInterface(ClassInterfaceType.None)]
    public class OAInfo : IDotNetInterface
    {

        public string version()
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            return asm.GetName().Name + " " + asm.GetName().Version;
        }

        public string SlicCertCompare(String slicPath, String certPath)
        {
            byte[] bin = File.ReadAllBytes(slicPath);
            bool standard = true;        
            string[] slic = new string[3];
            Encoding e = Encoding.GetEncoding(1252);
            string oemid = Encoding.ASCII.GetString(bin, 0x0A, 0x0E);
            slic[0] = e.GetString(bin, 0x0A, 6); //OEM ID
            slic[1] = e.GetString(bin, 0x10, 8); //OEM Table ID
            if (slic[0].Equals(e.GetString(bin, 0xCC, 6)) && slic[1].Equals(e.GetString(bin, 0xD2, 8)))
                standard = true;
            else if (slic[0].Equals(e.GetString(bin, 0x30, 6)) && slic[1].Equals(e.GetString(bin, 0x36, 8)))
                standard = false;

            try
            {
                return (Compare(slicPath, certPath, standard)).ToString();
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }

        }

        public string VerifySlic(String filePath)
        {
            bool standard = true;
            String filename = null;
            if (filePath.Length == 0)
            {
                return "No SLIC binary specified.";
            }
            else {
                filename = filePath;
            }

            // check file exists
            if (!File.Exists(filename))
            {
                return "The specified SLIC binary can not be found.";
            }

            // Create new FileInfo object and get the Length & Extension.
            FileInfo slicBinary = new FileInfo(filename);
            long fileSize = slicBinary.Length;
            string fileExt = slicBinary.Extension.ToUpperInvariant();

            if (fileExt != ".BIN")
            {
                return "SLIC binary should have the file extension *.BIN.";
            }

            if (fileSize != 374)
            {
                return "SLIC binary filesize mismatch, filesize should be 374 bytes.";
            }

            try
            {
                byte[] bin = File.ReadAllBytes(filename);
                //bool standard = true;        
                string[] slic = new string[3];
                Encoding e = Encoding.GetEncoding(1252);
                string oemid = Encoding.ASCII.GetString(bin, 0x0A, 0x0E);
                slic[0] = e.GetString(bin, 0x0A, 6); //OEM ID
                slic[1] = e.GetString(bin, 0x10, 8); //OEM Table ID
                if (slic[0].Equals(e.GetString(bin, 0xCC, 6)) && slic[1].Equals(e.GetString(bin, 0xD2, 8)))
                    standard = true;
                else if (slic[0].Equals(e.GetString(bin, 0x30, 6)) && slic[1].Equals(e.GetString(bin, 0x36, 8)))
                    standard = false;
                else
                {
                    return "SLIC Invalid, Inconsistent OEM/Table ID";
                }
                if (!(slic[0] + slic[1]).Equals(oemid))
                {
                    return "SLIC Invalid, Inconsistent X/RSDT OEM/Table ID";
                }
                if (!VerifySlicSignature(filename, standard))
                {
                    return "SLIC Digital Signature invalid";
                }
                else {
                    return "SLIC Digital Signature is valid";
                }

            }
            catch(Exception ex)
            {
                return ex.ToString();
            }
        }

        public string VerifyCert(String filePath)
        {
            String filename = null;
            if (filePath.Length == 0)
            {
                return "No OEM Certificate specified.";
            }
            else
            {
                filename = filePath;
            }

            // check file exists
            if (!File.Exists(filename))
            {
                return "The specified OEM Certificate can not be found.";
            }

            // Create new FileInfo object and get the Length & Extension.
            FileInfo cert = new FileInfo(filename);
            long fileSize = cert.Length;
            string fileExt = cert.Extension.ToUpperInvariant();


            if (!(fileExt != ".XRM-MS" ^ fileExt != ".XML"))
            {
                return "OEM Certificate should have the file extension *.XRM-MS or *.XML.";
            }

            if (fileSize != 2731)
            {
                return "OEM Certificate filesize mismatch, filesize should be 2.731 bytes.";
            }

            // check if the file valid XML format
            try
            {
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(filename);
            }
            catch (IOException)
            {
                if (fileExt == ".XRM-MS")
                {
                    return "Failed to open XrML file.";
                }
                else {
                    return "Failed to open xml file.";
                }
            }
            catch (XmlException)
            {
                if (fileExt == ".XRM-MS")
                {
                    return "Failed to read XrML file.";
                }
                else {
                    return "Failed to read xml file.";
                }
            }

            try
            {
                if (!VerifyCertSignature(filename))
                {
                    return "Certificate Digital Signature is invalid";
                }
                else
                {
                    return "Certificate Digital Signature is valid";
                }
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
        }
      
        /*
        /// <summary>
        /// Verifies the Digital Signature in the SLIC Table
        /// </summary>
        /// <param name="path">Path to the bin file</param>
        /// <returns>true if 'signature' matches the signature computed using the specified hash algorithm and key on 'messageHash'; otherwise, false.</returns>
        static bool VerifySlicSignature(string path)
        {
            byte[] bin = File.ReadAllBytes(path);
            byte[] exponent = new byte[4];
            byte[] modulus = new byte[128];
            byte[] message = new byte[46];
            byte[] signature = new byte[128];
            Array.Copy(bin, 0x3C, exponent, 0, exponent.Length);
            Array.Copy(bin, 0x40, modulus, 0, modulus.Length);
            Array.Copy(bin, 0xC8, message, 0, message.Length);
            Array.Copy(bin, 0xF6, signature, 0, signature.Length);
            Array.Reverse(exponent);
            Array.Reverse(modulus);
            RSAParameters parameter = new RSAParameters();
            parameter.Exponent = exponent;
            parameter.Modulus = modulus;
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSA.ImportParameters(parameter);
            RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(RSA);
            RSADeformatter.SetHashAlgorithm("SHA256");
            byte[] messageHash = new SHA256Managed().ComputeHash(message);
            bool verify = RSADeformatter.VerifySignature(messageHash, signature);
            return verify;
        }
        */
        /// <summary>
        /// Verifies the Digital Signature in the SLIC Table
        /// </summary>
        /// <param name="path">Path to the bin file</param>
        /// <param name="standard">Boolean Standard or Reversed</param>
        /// <returns>true if 'signature' matches the signature computed using the specified hash algorithm and key on 'messageHash'; otherwise, false.</returns>
        /// 
        static bool VerifySlicSignature(string path, bool standard)
        {
            byte[] bin = File.ReadAllBytes(path);
            byte[] exponent = new byte[4];
            byte[] modulus = new byte[128];
            byte[] message = new byte[46];
            byte[] signature = new byte[128];
            Array.Copy(bin, standard ? 0x3C : 0xF2, exponent, 0, exponent.Length);
            Array.Copy(bin, standard ? 0x40 : 0xF6, modulus, 0, modulus.Length);
            Array.Copy(bin, standard ? 0xC8 : 0x2C, message, 0, message.Length);
            Array.Copy(bin, standard ? 0xF6 : 0x5A, signature, 0, signature.Length);
            Array.Reverse(exponent);
            Array.Reverse(modulus);
            RSAParameters parameter = new RSAParameters();
            parameter.Exponent = exponent;
            parameter.Modulus = modulus;
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSA.ImportParameters(parameter);
            RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(RSA);
            RSADeformatter.SetHashAlgorithm("SHA256");
            byte[] messageHash = new SHA256Managed().ComputeHash(message);
            return RSADeformatter.VerifySignature(messageHash, signature);
        }

        /// <summary>
        /// Verifies the Signature and Licence Info in the Certificate
        /// </summary>
        /// <param name="path">Path to the certificate file</param>
        /// <returns>true if 'sign' matches the signature computed using the specified hash algorithm and key on 'Signature' and 'Digest' matches the computed hash for license; otherwise, false.</returns>
        static bool VerifyCertSignature(string path)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(path);
            XmlDsigC14NTransform transform = new XmlDsigC14NTransform();
            transform.LoadInput(new MemoryStream(Encoding.UTF8.GetBytes(doc.GetElementsByTagName("SignedInfo")[0].OuterXml)));
            byte[] siHash = transform.GetDigestedOutput(SHA1.Create());
            byte[] Signature = Convert.FromBase64String(doc.GetElementsByTagName("SignatureValue")[0].InnerText);
            byte[] Modulus = Convert.FromBase64String(doc.GetElementsByTagName("Modulus")[0].InnerText);
            byte[] Exponent = Convert.FromBase64String(doc.GetElementsByTagName("Exponent")[0].InnerText);
            string Digest = doc.GetElementsByTagName("DigestValue")[0].InnerText;
            RSAParameters parameter = new RSAParameters();
            parameter.Modulus = Modulus;
            parameter.Exponent = Exponent;
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(parameter);
            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA1");
            bool sign = rsaDeformatter.VerifySignature(siHash, Signature);
            XmlLicenseTransform License = new XmlLicenseTransform();
            License.Context = (XmlElement)doc.GetElementsByTagName("Signature")[0];
            License.LoadInput(doc);
            transform = new XmlDsigC14NTransform();
            transform.LoadInput(License.GetOutput());
            string dvHash = Convert.ToBase64String(transform.GetDigestedOutput(SHA1.Create()));
            return sign && dvHash.Equals(Digest);
        }

        /*
        /// <summary>
        /// Compare Certificate data and SLIC Table
        /// </summary>
        /// <param name="binFile">Path to bin file</param>
        /// <param name="certFile">Path to certificate file</param>
        /// <returns>true if data matches; otherwise false.</returns>
        static bool Compare(string binFile, string certFile)
        {
            byte[] bin = File.ReadAllBytes(binFile);
            XmlDocument doc = new XmlDocument();
            doc.Load(certFile);
            byte[] cert = Convert.FromBase64String(doc.GetElementsByTagName("sl:data")[0].InnerText);
            int i = 0;
            int j = 0;
            bool match = cert.Length == cert[i];
            for (i = 4, j = 0xC8; i < 14; i++, j++)
                match &= cert[i] == bin[j];
            for (j = 0x3C; i < cert.Length; i++, j++)
                match &= cert[i] == bin[j];
            return match;
        }
        */

        /// <summary>
        /// Compare Certificate data and SLIC Table
        /// </summary>
        /// <param name="path">Path to the bin file</param>
        /// <param name="certFile">Path to certificate file</param>
        /// <param name="standard">Boolean Standard or Reversed</param>
        /// <returns>true if data matches; otherwise false.</returns>
        static bool Compare(string binFile, string certFile, bool standard)
        {
            byte[] bin = File.ReadAllBytes(binFile);
            XmlDocument doc = new XmlDocument();
            doc.Load(certFile);
            byte[] cert = Convert.FromBase64String(doc.GetElementsByTagName("sl:data")[0].InnerText);
            int i = 0;
            int j = 0;
            bool match = cert.Length == cert[i];
            for (i = 4, j = standard ? 0xC8 : 0x2C; i < 14; i++, j++)
                match = match && cert[i] == bin[j];
            for (j = standard ? 0x3C : 0xF2; i < cert.Length; i++, j++)
                match = match && cert[i] == bin[j];
            return match;
        }

        /*
        private string offset(int i)
        {
            string str = Convert.ToString(i, 16).ToUpper();
            string s1 = "";
            for (int k = 8; k > str.Length; k--)
                s1 += "0";
            return s1 + str;
        }
        */

        public string Hexdump(string path)
        {
            String filename = null;
            if (path.Length == 0)
            {
                return "No SLIC binary specified.";
            }
            else
            {
                filename = path;
            }

            // check file exists
            if (!File.Exists(filename))
            {
                return "The specified SLIC binary can not be found.";
            }

            // Create new FileInfo object and get the Length & Extension.
            FileInfo slic = new FileInfo(filename);
            long fileSize = slic.Length;
            string fileExt = slic.Extension.ToUpperInvariant();

            if (fileExt != ".BIN")
            {
                return "SLIC binary should have the file extension *.BIN.";
            }

            if (fileSize != 374)
            {
                return "SLIC binary filesize mismatch, filesize should be 374 bytes.";
            }

            try
            {
                /*
                byte[] bins = File.ReadAllBytes(bin);
                //byte[] bins = System.Text.Encoding.Default.GetBytes(System.IO.File.ReadAllText(bin));
                string hex = "";
                for (int i = 0; i <= bins.Length; i += 16)
                {
                    int n = 0;
                    hex += offset(i) + "h: ";
                    while (n < 16)
                    {
                        if (!(i + n == bins.Length))
                        {
                            hex += String.Format("{0:x2}", bins[i + n]).ToUpper() + " ";
                            n++;
                        }
                        else
                        {
                            for (int k = n; k < 16; k++)
                                hex += "   ";
                            break;
                        }
                    }
                    n = 0;
                    while (n < 16)
                    {
                        if (!(i + n == bins.Length))
                        {
                            char ch = (char)bins[i + n];
                            //if (ch >= 32 && ch <= 255)
                            if (ch >= 32 && ch <= 255)
                            //if (ch >=32 && ch <=127) // ANSI Windows-1252.
                                hex += ((char)bins[i + n]).ToString();
                            else
                                hex += ".";
                            n++;
                        }
                        else
                            break;
                    }
                    hex += Environment.NewLine;
                }
                return hex;
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            */
    
            /*        
            byte[] bins = File.ReadAllBytes(bin);
            String hex = ""; 
            Encoding dos = Encoding.GetEncoding(1252);
            for(int i = 0; i <= bins.Length; i += 16) {	
              int n = 0;
              hex += String.Format("{0:x8}", i).ToUpper() + "h: ";
              while (n < 16) {
                if(!(i + n == bins.Length)) {
                  hex += String.Format("{0:x2}", bins[i + n]).ToUpper() + " ";
                  n++;
                }
	            else {
	              for(int k = n; k < 16; k++)
		            hex += "   ";
	              break;
	            } 
              }
              n = 0;
              while (n < 16) {
	            if(!(i + n == bins.Length)) {
  		            byte ch = bins[i + n];
  		            if(ch > 32)
  			            hex += dos.GetString(new byte[] {ch});
  		            else
  			            hex += '.';
  		            n++;
	            }
	            else
	             break; 
              }
        	  
              hex += Environment.NewLine;				
            }
            return hex;			
            }
            */
            byte[] bin = File.ReadAllBytes(filename);
            string dump = "";
            Encoding Latin = Encoding.GetEncoding(1252);
            for (int i = 0; i < bin.Length; i += 16)
            {
                string hexBlock = "";
                string stringBlock = "";
                dump += String.Format("{0:X8}h: ", i);
                for (int n = 0; n < 16; n++)
                {
                    if (!(i + n == bin.Length))
                    {
                        byte[] b = new byte[] { bin[i + n] };
                        hexBlock += String.Format("{0:X2} ", b[0]);
                        if (b[0] > 32)
                            stringBlock += Latin.GetString(b);
                        else
                            stringBlock += ".";
                    }
                    else
                    {
                        for (int k = n; k < 16; k++)
                            hexBlock += "   ";
                        break;
                    }
                }
                dump += hexBlock + stringBlock + Environment.NewLine;
            }
            return dump;
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }

        }
    }
}
