# Pack with .NETStandard2.1/.NETCore3.1/.NET6.0/.NET7.0 SDK

try {
    Push-Location
    cd ../../Nefe.Encryptor/
    dotnet pack -c Release
}
finally {
    Pop-Location
}