using System;
using System.Security.Cryptography;
using System.Text;

namespace Nefe.Encryptor
{
    /// <summary>
    /// The encryptor that is used to perform AES algorithm.
    /// </summary>
    public class AesEncryptor : IDisposable
    {
        #region [Private Properties]
        
        private Aes aesProvider = null!;
        
        #endregion

        #region [Public Properties]

        /// <summary>
        /// Gets or sets the secret key.
        /// </summary>
        public byte[] Key
        {
            get => this.aesProvider.Key;
            set => this.aesProvider.Key = value;
        }

        /// <summary>
        /// Gets or sets the initialization vector.
        /// </summary>
        public byte[] IV
        {
            get => this.aesProvider.IV;
            set => this.aesProvider.IV = value;
        }

        /// <summary>
        /// Creates a AES Encryptor
        /// </summary>
        public AesEncryptor(byte[] key, byte[]? iv = null, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            this.aesProvider = Aes.Create();
            this.aesProvider.Key = key;
            this.aesProvider.Mode = cipherMode;
            this.aesProvider.Padding = paddingMode;

            if (iv != null)
                this.aesProvider.IV = iv;
        }
        
        #endregion

        #region [Public Events]

        /// <summary>
        /// Creates a AES Encryptor by providing an IV encoded using UTF-8.
        /// </summary>
        public AesEncryptor(string key, string iv = null!, CipherMode cipherMode = CipherMode.CBC, PaddingMode paddingMode = PaddingMode.PKCS7) : this(Encoding.UTF8.GetBytes(key), iv == null ? null : Encoding.UTF8.GetBytes(iv), cipherMode, paddingMode) { }

        /// <summary>
        /// Releases all sources used.
        /// <summary/>
        public void Dispose() => this.aesProvider.Dispose();

        /// <summary>
        /// Generates a random key.
        /// </summary>
        /// <param name="length">The length of key.</param>
        /// <returns>The generated key.</returns>
        public static byte[] RandomKey(int length = 16)
        { 
            var random = new Random();
            var ret = new byte[length];

            for (int i = 0; i < length; ++i)
            {
                ret[i] = (byte)random.Next(0, 255);
            }

            return ret;
        }

        /// <summary>
        /// Generates a random string key.
        /// </summary>
        /// <param name="length">The length of key.</param>
        /// <returns>The generated key.</returns>
        public static string RandomKeyString(int length = 16)
        {
            var random = new Random();

            var ret = "";
            for (var i = 0; i < length; ++i)
            {
                var mode = random.Next(0, 3);
                if (mode == 0)
                    ret += (char)(random.Next(0, 15) + 33);
                else if(mode == 1)
                    ret += (char)(random.Next(0, 26) + 'A');
                else
                    ret += (char)(random.Next(0, 26) + 'a');
            }
            return ret;
        }

        /// <summary>
        /// Try to encrypt a piece of plaintext.
        /// </summary>
        /// <param name="data">The data that need to be encrypted.</param>
        /// <returns>The ciphertext.</returns>
        public byte[] Encrypt(byte[] data)
        {
            ICryptoTransform cTransform = aesProvider.CreateEncryptor();
            return cTransform.TransformFinalBlock(data, 0, data.Length);
        }
        
        /// <summary>
        /// Try to encrypt a piece of plaintext encoded using UTF-8.
        /// </summary>
        /// <param name="data">The data that need to be encrypted.</param>
        /// <returns>The ciphertext.</returns>
        public string Encrypt(string text) => Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(text)));

        /// <summary>
        /// Try to encrypt a piece of plaintext encoded by <paramref name="encoder"/>.
        /// </summary>
        /// <param name="data">The data that need to be encrypted.</param>
        /// <param name="encoder">The encoder used to decode text.</param>
        /// <returns>The ciphertext.</returns>
        public string Encrypt(string text, Encoding encoder) => Convert.ToBase64String(Encrypt(encoder.GetBytes(text)));

        /// <summary>
        /// Try to decrypt a piece of ciphertext.
        /// </summary>
        /// <param name="data">The data that need to be decrypted.</param>
        /// <returns>The plaintext.</returns>
        public byte[] Decrypt(byte[] data)
        {
            ICryptoTransform cTransform = aesProvider.CreateDecryptor();
            return cTransform.TransformFinalBlock(data, 0, data.Length);
        }

        /// <summary>
        /// Try to decrypt a piece of ciphertext encoded using UTF-8.
        /// </summary>
        /// <param name="data">The data that need to be decrypted.</param>
        /// <returns>The plaintext.</returns>
        public string Decrypt(string text) => Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(text)));

        /// <summary>
        /// Try to decrypt a piece of ciphertext encoded by <paramref name="encoder"/>.
        /// </summary>
        /// <param name="data">The data that need to be decrypted.</param>
        /// <param name="encoder">The encoder used to decode text.</param>
        /// <returns>The plaintext.</returns>
        public string Decrypt(string text, Encoding encoder) => encoder.GetString(Decrypt(Convert.FromBase64String(text)));
        
        #endregion
    }
}
