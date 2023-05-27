using System.Security.Cryptography;
using System.Text;
using Nefe.Encryptor;

void WriteColoredLine(string text, ConsoleColor color = ConsoleColor.Green)
{
    Console.ForegroundColor = color;
    Console.WriteLine(text);
    Console.ResetColor();
}

// AES Test
WriteColoredLine("AES Test");
var aes = new AesEncryptor(AesEncryptor.RandomKey(), AesEncryptor.RandomKey(), CipherMode.ECB, PaddingMode.PKCS7);
var tmp = aes.Encrypt("Hello");
Console.WriteLine(Convert.ToBase64String(aes.Key));
Console.WriteLine(Convert.ToBase64String(aes.IV));
Console.WriteLine(tmp);
Console.WriteLine(aes.Decrypt(tmp));

Console.WriteLine();

WriteColoredLine("RSA Test");
var rsaKey = "";
var rsaPublicKey = "";
RsaEncryptor.RandomKeyXmlString(out rsaKey, out rsaPublicKey, 512);
var rsaEncrypt = new RsaEncryptor(rsaPublicKey);
tmp = rsaEncrypt.Encrypt("Hello, Nefe.Encryption");
// Console.WriteLine(rsaEncrypt.XmlPublicKey);
Console.WriteLine(tmp);
var rsaDecrypt = new RsaEncryptor(rsaKey);
// Console.WriteLine(rsaDecrypt.XmlKey);
Console.WriteLine(rsaDecrypt.Decrypt(tmp));

Console.WriteLine($"Data Verified: {rsaEncrypt.VerifyData(Encoding.UTF8.GetBytes("wsl ak ioi"), rsaDecrypt.Sign(Encoding.UTF8.GetBytes("wsl ak ioi")))}");
Console.WriteLine($"Hash Verfied: {rsaEncrypt.VerifyHash(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("wsl ak ioi")), rsaDecrypt.Sign(Encoding.UTF8.GetBytes("wsl ak ioi")))}");
Console.WriteLine();

WriteColoredLine("MD5 Test");
Console.WriteLine(BytesFormatter.Format(MD5.Create().ComputeHash(Encoding.UTF8.GetBytes("Goodbye, MD5")), "-"));

Console.WriteLine();

WriteColoredLine("SHA-256 Test");
Console.WriteLine(BytesFormatter.Format(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("Hello, SHA-256")), "-"));