using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Nefe.Encryptor
{
    /// <summary>
    /// The encryptor that is used to perform RSA algorithm.
    /// </summary>
    public class RsaEncryptor : IDisposable
    {
        #region [Private Properties]

        private RSACryptoServiceProvider rsaProvider = null!;

        #endregion

        #region [Public Properties]

        /// <summary>
        /// Gets the PKCS#1 private key.
        /// </summary>
        public byte[] Pkcs1PrivateKey
        {
            get => this.rsaProvider.ExportRSAPrivateKey();
        }

        /// <summary>
        /// Gets the PKCS#1 public key.
        /// </summary>
        public byte[] Pkcs1PublicKey
        {
            get => this.rsaProvider.ExportRSAPublicKey();
        }
        
        /// <summary>
        /// Gets the PKCS#8 private key.
        /// </summary>
        public byte[] Pkcs8PrivateKey
        {
            get => this.rsaProvider.ExportPkcs8PrivateKey();
        }

        /// <summary>
        /// Gets the public and private key.
        /// </summary>
        public string XmlKey
        {
            get => this.rsaProvider.ToXmlString(true);
        }

        /// <summary>
        /// Gets the public key.
        /// </summary>
        public string XmlPublicKey
        {
            get => this.rsaProvider.ToXmlString(false);
        }

        #endregion

        #region [Public Events]

        /// <summary>
        /// Creates a AES Encryptor
        /// </summary>
        public RsaEncryptor(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Invalid Public Key");

            this.rsaProvider = new RSACryptoServiceProvider();
            this.rsaProvider.FromXmlString(key);
        }

        /// <summary>
        /// Releases all sources used.
        /// <summary/>
        public void Dispose() => this.rsaProvider.Dispose();

        /// <summary>
        /// Generates a random key.
        /// </summary>
        /// <param name="privateKey">The generated private key.</param>
        /// <param name="publickey">The generated public key.</param>
        /// <param name="length">The length of key.</param>
        public static void RandomKey(out byte[] privateKey, out byte[] publickey, int length = 4096)
        {
            using var rsa = new RSACryptoServiceProvider(length);
            privateKey = rsa.ExportRSAPrivateKey();
            publickey = rsa.ExportRSAPublicKey();
        }

        /// <summary>
        /// Generates a random xml-string key.
        /// </summary>
        /// <param name="privateKey">The generated private and public key.</param>
        /// <param name="publickey">The generated public key.</param>
        /// <param name="length">The length of key.</param>
        public static void RandomKeyXmlString(out string xmlKey, out string xmlPublicKey, int length = 4096)
        {
            using var rsa = new RSACryptoServiceProvider(length);
            xmlKey = rsa.ToXmlString(true);
            xmlPublicKey = rsa.ToXmlString(false);
        }
        
        /// <summary>
        /// Gets the encrypted PKCS#8 private key.
        /// </summary>
        public byte[] EncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters)
        {
            return this.rsaProvider.ExportEncryptedPkcs8PrivateKey(passwordBytes, pbeParameters);
        }

        /// <summary>
        /// Try to encrypt a piece of plaintext.
        /// </summary>
        /// <param name="data">The data that need to be encrypted.</param>
        /// <returns>The ciphertext.</returns>
        public byte[] Encrypt(byte[] data)
        {
            var bufferSize = (this.rsaProvider.KeySize / 8) - 11;
            var buffer = new byte[bufferSize];

            // Encrypts in segments
            using MemoryStream inputStream = new MemoryStream(data), outputStream = new MemoryStream();
            while (true)
            {
                var readSize = inputStream.Read(buffer, 0, bufferSize);
                
                if (readSize <= 0)
                    break;

                var temp = new byte[readSize];
                Array.Copy(buffer, 0, temp, 0, readSize);
                var encryptedBytes = this.rsaProvider.Encrypt(temp, false);
                outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
            }

            return outputStream.ToArray();
        }

        /// <summary>
        /// Try to encrypt a piece of plaintext encoded using UTF-8.
        /// </summary>
        /// <param name="data">The data that need to be encrypted.</param>
        /// <returns>The ciphertext.</returns>
        public string Encrypt(string data) => Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(data)));

        /// <summary>
        /// Try to encrypt a piece of plaintext encoded by <paramref name="encoder"/>.
        /// </summary>
        /// <param name="data">The data that need to be encrypted.</param>
        /// <param name="encoder">The encoder used to decode text.</param>
        /// <returns>The ciphertext.</returns>
        public string Encrypt(string data, Encoding encoder) => Convert.ToBase64String(Encrypt(encoder.GetBytes(data)));

        /// <summary>
        /// Try to decrypt a piece of ciphertext.
        /// </summary>
        /// <param name="data">The data that need to be decrypted.</param>
        /// <returns>The plaintext.</returns>
        public byte[] Decrypt(byte[] data)
        {
            var bufferSize = this.rsaProvider.KeySize / 8;
            var buffer = new byte[bufferSize];
            
            // Decrypts in segments
            using MemoryStream inputStream = new MemoryStream(data), outputStream = new MemoryStream();
            while (true)
            {
                int readSize = inputStream.Read(buffer, 0, bufferSize);
                
                if (readSize <= 0)
                    break;

                var temp = new byte[readSize];
                Array.Copy(buffer, 0, temp, 0, readSize);
                var rawBytes = this.rsaProvider.Decrypt(temp, false);
                outputStream.Write(rawBytes, 0, rawBytes.Length);
            }
            
            return outputStream.ToArray();
        }

        /// <summary>
        /// Try to decrypt a piece of ciphertext encoded using UTF-8.
        /// </summary>
        /// <param name="data">The data that need to be decrypted.</param>
        /// <returns>The plaintext.</returns>
        public string Decrypt(string data) => Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(data)));

        /// <summary>
        /// Try to decrypt a piece of ciphertext encoded by <paramref name="encoder"/>.
        /// </summary>
        /// <param name="data">The data that need to be decrypted.</param>
        /// <param name="encoder">The encoder used to decode text.</param>
        /// <returns>The plaintext.</returns>
        public string Decrypt(string data, Encoding encoder) => encoder.GetString(Decrypt(Convert.FromBase64String(data)));

        /// <summary>
        /// Try to sign the data with SHA-256.
        /// <param name="data">The data that need to be signed.</param>
        /// <return>The result.</return>
        /// </summary>
        public byte[] Sign(byte[] data) => this.Sign(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        /// <summary>
        /// Try to sign the data with SHA-256.
        /// <param name="data">The data that need to be signed.</param>
        /// <param name="algorithmName">The digest algorithm used.</param>
        /// <return>The digital signature.</return>
        /// </summary>
        public byte[] Sign(byte[] data, HashAlgorithmName algorithmName) => this.Sign(data, algorithmName, RSASignaturePadding.Pkcs1);
        
        /// <summary>
        /// Try to sign the data with SHA-256.
        /// <param name="data">The data that need to be signed.</param>
        /// <param name="algorithmName">The digest algorithm used.</param>
        /// <param name="paddingMode">The padding mode used.</param>
        /// <return>The digital signature.</return>
        /// </summary>
        public byte[] Sign(byte[] data, HashAlgorithmName algorithmName, RSASignaturePadding paddingMode)
        {
            return this.rsaProvider.SignData(data, algorithmName, paddingMode);
        }

        /// <summary>
        /// Verify the signature.
        /// <param name="data">The raw data.</param>
        /// <param name="signature">The digital signature that need to be verified.</param>
        /// <return>True if the signature is valid; otherwise, false.</return>
        /// </summary>
        public bool VerifyData(byte[] data, byte[] signature) => this.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        /// <summary>
        /// Verify the signature.
        /// <param name="data">The raw data.</param>
        /// <param name="signature">The digital signature that need to be verified.</param>
        /// <param name="algorithmName">The digest algorithm used.</param>
        /// <return>True if the signature is valid; otherwise, false.</return>
        /// </summary>
        public bool VerifyData(byte[] data, byte[] signature, HashAlgorithmName algorithmName) => this.VerifyData(data, signature, algorithmName, RSASignaturePadding.Pkcs1);
        
        /// <summary>
        /// Verify the signature.
        /// <param name="data">The raw data.</param>
        /// <param name="signature">The digital signature that need to be verified.</param>
        /// <param name="algorithmName">The digest algorithm used.</param>
        /// <param name="paddingMode">The padding mode used.</param>
        /// <return>True if the signature is valid; otherwise, false.</return>
        /// </summary>
        public bool VerifyData(byte[] data, byte[] signature, HashAlgorithmName algorithmName, RSASignaturePadding paddingMode)
        {
            return this.rsaProvider.VerifyData(data, signature, algorithmName, paddingMode);
        }
        
        /// <summary>
        /// Verifies the hashed signature.
        /// <param name="hash">The hashed data.</param>
        /// <param name="signature">The digital signature that need to be verified.</param>
        /// <return>True if the signature is valid; otherwise, false.</return>
        /// </summary>
        public bool VerifyHash(byte[] hash, byte[] signature) => this.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        /// <summary>
        /// Verifies the hashed signature.
        /// <param name="hash">The hashed data.</param>
        /// <param name="signature">The digital signature that need to be verified.</param>
        /// <param name="algorithmName">The digest algorithm used.</param>
        /// <return>True if the signature is valid; otherwise, false.</return>
        /// </summary>
        public bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName algorithmName) => this.VerifyHash(hash, signature, algorithmName, RSASignaturePadding.Pkcs1);
        
        /// <summary>
        /// Verifies the hashed signature.
        /// <param name="hash">The hashed data.</param>
        /// <param name="signature">The digital signature that need to be verified.</param>
        /// <param name="algorithmName">The digest algorithm used.</param>
        /// <param name="paddingMode">The padding mode used.</param>
        /// <return>True if the signature is valid; otherwise, false.</return>
        /// </summary>
        public bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName algorithmName, RSASignaturePadding paddingMode)
        {
            return this.rsaProvider.VerifyHash(hash, signature, algorithmName, paddingMode);
        }
        
        #endregion
    }
}
