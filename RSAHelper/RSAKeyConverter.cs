namespace Laggage.RSAHelper
{
    using System;
    using System.Security.Cryptography;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.X509;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Crypto.Parameters;

    public class RSAKeyConverter
    {
        /// <summary>
        /// xml private key -> base64 private key string
        /// </summary>
        /// <param name="xmlPrivateKey">RSA private key has format of xml</param>
        /// <returns>Normal RSA private key</returns>
        public static string FromXmlPrivateKey(string xmlPrivateKey)
        {
            string result = string.Empty;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPrivateKey);
                RSAParameters param = rsa.ExportParameters(true);
                RsaPrivateCrtKeyParameters privateKeyParam = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, param.Modulus), new BigInteger(1, param.Exponent),
                    new BigInteger(1, param.D), new BigInteger(1, param.P),
                    new BigInteger(1, param.Q), new BigInteger(1, param.DP),
                    new BigInteger(1, param.DQ), new BigInteger(1, param.InverseQ));
                PrivateKeyInfo privateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParam);

                result = Convert.ToBase64String(privateKey.ToAsn1Object().GetEncoded());
            }
            return result;
        }

        /// <summary>
        /// xml public key -> base64 public key string
        /// </summary>
        /// <param name="xmlPublicKey">RSA public key has format of xml</param>
        /// <returns>Normal RSA public key</returns>
        public static string FromXmlPublicKey(string xmlPublicKey)
        {
            string result = string.Empty;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(xmlPublicKey);
                RSAParameters p = rsa.ExportParameters(false);
                RsaKeyParameters keyParams = new RsaKeyParameters(
                    false, new BigInteger(1, p.Modulus), new BigInteger(1, p.Exponent));
                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyParams);
                result = Convert.ToBase64String(publicKeyInfo.ToAsn1Object().GetEncoded());
            }
            return result;
        }

        /// <summary>
        /// Base64 RSA private key string -> xml private key
        /// </summary>
        /// <param name="privateKey">normal RSA private key</param>
        /// <returns>RSA private key has format of xml</returns>
        public static string ToXmlPrivateKey(string privateKey)
        {
            RsaPrivateCrtKeyParameters privateKeyParams =
                PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey)) as RsaPrivateCrtKeyParameters;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                RSAParameters rsaParams = new RSAParameters()
                {
                    Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned(),
                    Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned(),
                    D = privateKeyParams.Exponent.ToByteArrayUnsigned(),
                    DP = privateKeyParams.DP.ToByteArrayUnsigned(),
                    DQ = privateKeyParams.DQ.ToByteArrayUnsigned(),
                    P = privateKeyParams.P.ToByteArrayUnsigned(),
                    Q = privateKeyParams.Q.ToByteArrayUnsigned(),
                    InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned()
                };
                rsa.ImportParameters(rsaParams);
                return rsa.ToXmlString(true);
            }
        }

        /// <summary>
        /// Base64 RSA public key string -> xml public key
        /// </summary>
        /// <param name="pubilcKey">Normal RSA public key</param>
        /// <returns>RSA public key has format of xml</returns>
        public static string ToXmlPublicKey(string pubilcKey)
        {
            RsaKeyParameters p =
                PublicKeyFactory.CreateKey(Convert.FromBase64String(pubilcKey)) as RsaKeyParameters;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                RSAParameters rsaParams = new RSAParameters
                {
                    Modulus = p.Modulus.ToByteArrayUnsigned(),
                    Exponent = p.Exponent.ToByteArrayUnsigned()
                };
                rsa.ImportParameters(rsaParams);
                return rsa.ToXmlString(false);
            }
        }
    }
}
