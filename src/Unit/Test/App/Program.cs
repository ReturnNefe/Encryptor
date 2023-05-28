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
using var aes = new AesEncryptor(RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(16), CipherMode.ECB, PaddingMode.PKCS7);
var tmp = aes.Encrypt(Encoding.UTF8.GetBytes("Hello"));
Console.WriteLine(Convert.ToBase64String(tmp));
Console.WriteLine(Encoding.UTF8.GetString(aes.Decrypt(tmp)));

Console.WriteLine();

// RSA Test
WriteColoredLine("RSA Test");
var rsaKey = "";
var rsaPublicKey = "";
RsaEncryptor.RandomKeyXmlString(out rsaKey, out rsaPublicKey, 512);
using var rsaEncryptor = new RsaEncryptor(rsaPublicKey);
tmp = rsaEncryptor.Encrypt(Encoding.UTF8.GetBytes("Hello, Nefe.Encryptor"));
// Console.WriteLine(Convert.ToBase64String(rsaEncryptor.Pkcs1PublicKey));
Console.WriteLine(Convert.ToBase64String(tmp));
using var rsaDecryptor = new RsaEncryptor(rsaKey);
// Console.WriteLine(Convert.ToBase64String(rsaDecryptor.Pkcs1PrivateKey));
Console.WriteLine(Encoding.UTF8.GetString(rsaDecryptor.Decrypt(tmp)));

Console.WriteLine($"Data Verified: {rsaEncryptor.VerifyData(Encoding.UTF8.GetBytes("nefe"), rsaDecryptor.Sign(Encoding.UTF8.GetBytes("nefe")))}");
Console.WriteLine($"Hash Verfied: {rsaEncryptor.VerifyHash(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("nefe")), rsaDecryptor.Sign(Encoding.UTF8.GetBytes("nefe")))}");
Console.WriteLine();

// MD5 Test
WriteColoredLine("MD5 Test");
Console.WriteLine(BytesFormatter.Format(MD5.Create().ComputeHash(Encoding.UTF8.GetBytes("Goodbye, MD5")), "-"));

Console.WriteLine();

// SHA0256 Test
WriteColoredLine("SHA-256 Test");
Console.WriteLine(BytesFormatter.Format(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("Hello, SHA-256")), "-"));