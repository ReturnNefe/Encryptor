# Nefe.Encryptor

[![Nuget Download](https://img.shields.io/nuget/dt/Nefe.Encryptor?style=flat-square)](https://www.nuget.org/packages/Nefe.Encryptor/) ![GitHub](https://img.shields.io/github/license/ReturnNefe/Encryptor?style=flat-square)

An Encryptor on .NET.

## Requirements

.NET Standard 2.1 / .NET 7 / .NET 6 / .NET Core 3.1

## Install

```shell
dotnet add package Nefe.Encryptor
```

## Usage

References the namespace.

```csharp
using Nefe.Encryptor;
```

**AES Algorithm**

```csharp
using (var aes = new AesEncryptor(RandomNumberGenerator.GetBytes(16)))
{
    // Encrypt it
    var cipherText = aes.Encrypt(Encoding.UTF8.GetBytes("Hello, AES."));
    Console.WriteLine(Convert.ToBase64String(cipherText));
    // Decrypt it
    Console.WriteLine(Encoding.UTF8.GetString(aes.Decrypt(cipherText)));
}
```

**RSA Algorithm**
```csharp
using (var rsaEncryptor = new RsaEncryptor())
{
    // Encrypt
    var cipherText = rsaEncryptor.Encrypt(Encoding.UTF8.GetBytes("Hello, RSA."));
    Console.WriteLine(Convert.ToBase64String(cipherText));
    
    // Decrypt and Verify
    using(var rsaDecryptor = new RsaEncryptor(rsaEncryptor.XmlKey))
    {
        Console.WriteLine(Encoding.UTF8.GetString(rsaDecryptor.Decrypt(cipherText)));

        Console.WriteLine($"Data Verified: {rsaEncryptor.VerifyData(Encoding.UTF8.GetBytes("nefe"), rsaDecryptor.Sign(Encoding.UTF8.GetBytes("rsa")))}");
        
        Console.WriteLine($"Hash Verfied: {rsaEncryptor.VerifyHash(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("rsa")), rsaDecryptor.Sign(Encoding.UTF8.GetBytes("rsa")))}");
    }
}
```

