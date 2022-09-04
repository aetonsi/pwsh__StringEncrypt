
# https://saemundsson.se/2015/04/01/encrypting-strings-with-custom-keys-in-powershell/
function Get-AesEncryptionKey {
    Param(
        [Parameter(Mandatory = $false)] [ValidateSet(16, 24, 32)] [int] $bytes = 32 # You can use 16, 24, or 32 for AES
    )

    $bytesArray = New-Object Byte[] $bytes
    [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytesArray)
    return $bytesArray
}
function ConvertTo-EncryptedString {
    Param(
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeLine = $true)][Alias("String")][AllowEmptyString()][String]$PlainTextString,
        [Parameter(Mandatory = $True, Position = 1)][Alias("Key")][byte[]]$EncryptionKey
    )
    if ('' -eq $PlainTextString -or $null -eq $PlainTextString) {
        return ''
    }
    Try {
        $secureString = Convertto-SecureString $PlainTextString -AsPlainText -Force
        $EncryptedString = ConvertFrom-SecureString -SecureString $secureString -Key $EncryptionKey

        return $EncryptedString
    }
    Catch { Throw $_ }
}
Function ConvertFrom-EncryptedString {
    Param(
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeLine = $true)][Alias("String")][AllowEmptyString()][String]$EncryptedString,
        [Parameter(Mandatory = $True, Position = 1)][Alias("Key")][byte[]]$EncryptionKey
    )
    if ('' -eq $EncryptedString -or $null -eq $EncryptedString) {
        return ''
    }
    Try {
        $SecureString = ConvertTo-SecureString $EncryptedString -Key $EncryptionKey
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        [string]$String = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        Return $String
    }
    Catch { Throw $_ }
}


Export-ModuleMember -Function *