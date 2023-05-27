using System.Security.Cryptography;
using System.Text;

namespace Nefe.Encryptor
{
    /// <summary>
    /// The encryptor that is used to perform MD5 algorithm.
    /// </summary>
    public class BytesFormatter
    {
        #region [Public Events]
        
        /// <summary>
        /// Formats the bytes.
        /// </summary>
        /// <param name="data">The data that need to be formatted.</param>
        /// <param name="separator">The separator used to split byte.</param>
        /// <param name="format">The formator of byte.</param>
        /// <returns>The formatted string.</returns>
        public static string Format(byte[] data, string separator = "-", string format = "X2")
        {
            var result = "";

            foreach (var iter in data)
                result += $"{iter.ToString(format)}{separator}";

            return result[..^separator.Length];
        }
        
        #endregion
    }
}
