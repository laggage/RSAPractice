namespace RSA
{
    using Laggage.RSAHelper;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using System.Xml;


    struct RSASecretKey
    {
        public RSASecretKey(string privateKey, string publicKey)
        {
            PrivateKey = privateKey;
            PublicKey = publicKey;
        }
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public override string ToString()
        {
            return string.Format(
                "PrivateKey: {0}\r\nPublicKey: {1}", PrivateKey, PublicKey);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            //Set input buffer of Console,default input buffer size is 128 byte,which is not enough.
            Console.SetIn(new StreamReader(Console.OpenStandardInput(500), Console.InputEncoding));

            Program program = new Program();
            bool exit = false;
            while(!exit)
            {
                exit = program.ShowMainPage();
            }
        }

        private List<RSASecretKey> _generatedRSAKey;

        public Program()
        {
            _generatedRSAKey = new List<RSASecretKey>();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns> if true:Exit the program; else continue; </returns>
        bool ShowMainPage()
        {
            Console.Clear();
            Console.WriteLine("----- C# RSA 操作示例 -----");
            Console.WriteLine("1.生成RSA密钥;");
            Console.WriteLine("2.加密数据;");
            Console.WriteLine("3.解密数据;");
            Console.WriteLine("4.列出密钥;");
            Console.WriteLine("0.退出;");
            Console.WriteLine("--------------------------");

            int chooseIndex = int.Parse(Console.ReadLine());
            switch(chooseIndex)
            {
                case 1:
                    ShowCreateRSAKeyPage();
                    break;
                case 2:
                    ShowEncryptPage(); break;
                case 3:
                    ShowDecryptPage();
                    break;
                case 4:
                    ShowDisplayRSAKeyPage();
                    break;
                case 0:
                    return true;
                default:break;
            }
            return false;
        }

        void ShowCreateRSAKeyPage()
        {
            Console.Clear();
            Console.WriteLine("----- C# RSA 操作示例 -----");
            Console.Write("RSA密钥位数:");
            int rsaKeySize = int.Parse(Console.ReadLine());
            RSASecretKey rsaKey = GenerateRSASecretKey(rsaKeySize);
            _generatedRSAKey.Add(rsaKey);
            DisplayRSAKey(rsaKey);
            Console.ReadKey();
        }

        void ShowEncryptPage()
        {
            Console.Clear();
            Console.WriteLine("----- C# RSA 操作示例 -----");
            int i = 0;
            foreach(RSASecretKey key in _generatedRSAKey)
            {
                Console.WriteLine("{0}:{1}",++i, key.PublicKey);
            }
            Console.Write("选择密钥:");
            int ch = int.Parse(Console.ReadLine());
            Console.Write("\r\n要加密的内容:");
            string content = Console.ReadLine();
            string encryptedContent = RSAEncrypt(/*_generatedRSAKey[ch - 1].PublicKey*/RSAKeyConverter.ToXmlPublicKey(_generatedRSAKey[ch - 1].PublicKey), content);
            Console.WriteLine("Result: {0}", encryptedContent);
            Console.ReadKey();
        }

        void ShowDecryptPage()
        {
            Console.Clear();
            Console.WriteLine("----- C# RSA 操作示例 -----");
            int i = 0;
            foreach (RSASecretKey key in _generatedRSAKey)
            {
                Console.WriteLine("{0}:{1}", ++i, key.PrivateKey);
            }
            Console.Write("选择密钥:");
            int ch = int.Parse(Console.ReadLine());
            Console.Write("\r\n要解密的内容:");
            string content = Console.ReadLine();
            string decryptedContent = RSADecrypt(/*_generatedRSAKey[ch - 1].PrivateKey*/RSAKeyConverter.ToXmlPrivateKey(_generatedRSAKey[ch - 1].PrivateKey), content);
            Console.WriteLine("Result: {0}", decryptedContent);
            Console.ReadKey();
        }

        void ShowDisplayRSAKeyPage()
        {
            Console.Clear();
            Console.WriteLine("----- C# RSA 操作示例 -----");
            Console.WriteLine("1.普通格式;");
            Console.WriteLine("2.xml格式;");
            int ch = int.Parse(Console.ReadLine());
            switch (ch)
            {
                case 1:
                    DisplayRSAKey(_generatedRSAKey);
                    break;
                case 2:
                    DisplayRSAKeyInXml(_generatedRSAKey);
                    break;
                default:
                    break;
            }
            Console.ReadKey();
        }

        void DisplayRSAKey(IEnumerable<RSASecretKey> keys,bool showPublicKey = true,bool showPrivateKey = true)
        {
            foreach(var key in keys)
            {
                DisplayRSAKey(key, showPublicKey, showPrivateKey);
            }
        }

        void DisplayRSAKey(RSASecretKey key, bool showPublicKey = true, bool showPrivateKey = true)
        {
            if (showPrivateKey)
            {
                Write(ConsoleColor.Green, "PrivateKey:");
                Console.WriteLine(key.PrivateKey);
            }
            if (showPublicKey)
            {
                Write(ConsoleColor.Green, "PublicKey:");
                Console.WriteLine(key.PublicKey);
            }
        }

        void DisplayRSAKeyInXml(RSASecretKey key,bool showPublicKey = true, bool showPrivateKey = true)
        {
            if (showPrivateKey)
            {
                Write(ConsoleColor.Green, "PrivateKey:");
                Console.WriteLine(FormatXml(RSAKeyConverter.ToXmlPrivateKey(key.PrivateKey)));
            }
            if (showPublicKey)
            {
                Write(ConsoleColor.Green, "PublicKey:");
                Console.WriteLine(FormatXml(RSAKeyConverter.ToXmlPublicKey(key.PublicKey)));
            }
        }

        private string FormatXml(string xml)
        {
            string res = string.Empty;
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);
            try
            {
                using (StringWriter sw = new StringWriter())
                {
                    using (XmlTextWriter xmlWriter = new XmlTextWriter(sw))
                    {
                        xmlWriter.Indentation = 2;
                        xmlWriter.Formatting = Formatting.Indented;
                        doc.WriteContentTo(xmlWriter);
                        xmlWriter.Close();
                    }
                    res = sw.ToString();
                    sw.Close();
                }
                return res;
            }
            catch
            {
                return xml;
            }
        }

        void DisplayRSAKeyInXml(IEnumerable<RSASecretKey> keys, bool showPublicKey = true, bool showPrivateKey = true)
        {
            foreach(RSASecretKey key in keys)
            {
                DisplayRSAKeyInXml(key, showPublicKey, showPrivateKey);
            }
        }

        void Write(ConsoleColor textColor,string value,params object[] args)
        {
            ConsoleColor originColor = Console.ForegroundColor;
            Console.ForegroundColor = textColor;
            Console.Write(value, args);
            Console.ForegroundColor = originColor;
        }

        void Write(ConsoleColor textColor,string value)
        {
            Write(textColor, value, null);
        }
        /// <summary>
        /// generate RSA secret key
        /// </summary>
        /// <param name="keySize">the size of the key,must from 384 bits to 16384 bits in increments of 8 </param>
        /// <returns></returns>
        RSASecretKey GenerateRSASecretKey(int keySize)
        {
            if (keySize % 8 != 0 || keySize < 384 || keySize > 16384)
                throw new ArgumentOutOfRangeException(nameof(keySize), "The range of KeySize must from 384 bits to 16384 bits in increments of 8");
            RSASecretKey rsaKey = new RSASecretKey();
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize))
            {
                rsaKey.PrivateKey = rsa.ToXmlString(true);
                rsaKey.PublicKey = rsa.ToXmlString(false);
            }
            rsaKey.PrivateKey = RSAKeyConverter.FromXmlPrivateKey(rsaKey.PrivateKey);
            rsaKey.PublicKey = RSAKeyConverter.FromXmlPublicKey(rsaKey.PublicKey);
            return rsaKey;
        }

        string RSAEncrypt(string xmlPublicKey,string content)
        {
            string encryptedContent = string.Empty;
            using(RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPublicKey);
                byte[] encryptedData = rsa.Encrypt(Encoding.Default.GetBytes(content), false);
                encryptedContent = Convert.ToBase64String(encryptedData);
            }
            return encryptedContent;
        }

        string RSADecrypt(string xmlPrivateKey, string content)
        {
            string decryptedContent = string.Empty;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPrivateKey);
                byte[] decryptedData = rsa.Decrypt(Convert.FromBase64String(content), false);
                decryptedContent = Encoding.GetEncoding("gb2312").GetString(decryptedData);
            }
            return decryptedContent;
        }
    }
}
