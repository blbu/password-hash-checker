<#
.SYNOPSIS
Submits part of a password hash to pwnedpassword.com to tell you if your password has been compromised.
#>

# Your password
$PasswordString = "P@ssw0rd";

# The hash algorithm used by the "pwnedpasswords" website
$HashName = 'SHA1';

# Convert the password to UTF-8, a generic encoding
$PasswordAsUTF8 = [System.Text.Encoding]::UTF8.GetBytes($PasswordString);

# Use built-in hashing, hash password to SHA1 and convert back to text
$StringBuilder = New-Object System.Text.StringBuilder;
$Hasher = [System.Security.Cryptography.HashAlgorithm]::Create($HashName);
$Hasher.ComputeHash($PasswordAsUTF8)|% { [Void]$StringBuilder.Append($_.ToString("x2")); }
$HashedPassword = $StringBuilder.ToString();

# Send the first five characters to the service, check if the rest is in the answer.
# This is known as "k-anonymity"--you give away PART of a hash of your password, but they can't work out which suffix was yours.
$HashedPasswordPrefix = $HashedPassword.SubString(0, 5);
$HashedPasswordSuffix = $HashedPassword.SubString(5);

# The service requires at least TLS 1.2 (PowerShell defaults to TLS 1.0)--better security to use TLS 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# This is the service which will respond with the suffixes of our hashes.
$PasswordHashRangeUrl = 'https://api.pwnedpasswords.com/range/' + $HashedPasswordPrefix
Write-Host "Checking $PasswordHashRangeUrl (you can open this in your web browser)"

# Get the content of the response
$HashedSuffixes = Invoke-WebRequest $PasswordHashRangeUrl | Select -ExpandProperty Content

# If the suffix of our hash is in the content, then our password is compromised.
$PwnedPassword = $HashedSuffixes.ToUpperInvariant().Contains($HashedPasswordSuffix.ToUpperInvariant());

if ($PwnedPassword) {
    Write-Host "That password has been compromised, you should change it."
} else {
    Write-Host "That password is not in *this* data, but doesn't guarantee it is safe. Follow best practices."
}
