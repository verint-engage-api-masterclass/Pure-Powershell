# Command Line Parameters
param(
    [Parameter(Mandatory=$true)]
    [string]$empID					# Verint empID used to identify the employee
)


echo $empID

$APIKeyId = "your_api_key_id_here"
$APIKey = "your_api_key_here"
$SERVER = "wfo.<xxx>.verintcloudservices.com"

$URL = "https://$SERVER/wfo/user-mgmt-api/v1/employees/$empID"
$method = "GET"


Function getAuthHeader($url, $method, $key) {
    $random = New-Object Byte[] 16
    $RNGCrypto = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $RNGCrypto.GetBytes($random)

    $uri = [System.Uri]$URL
    $path = $uri.AbsolutePath

    $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $salt = -join (Get-Random -Count 20 -InputObject $characters)

    $issuedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $stringToSign = "$($salt)`n$($method)`n$($path)`n$($issuedAt)`n`n"			#Unique string for each API
	
	
	# Prep the API Key into base64 string
	$key = $key + ('=' * ((4 - ($key.Length % 4)) % 4))				# Add padding '='
	$key = $key.Replace('-', '+').Replace('_', '/')					# Replace non-base64 characters with base64 characters
	Write-Debug " API Key after transform: $key`n"

	# Crypto
	$hmacsha = New-Object System.Security.Cryptography.HMACSHA256							# initialize the cypto object
	$hmacsha.key = [System.Convert]::FromBase64String($key)									# Converts the API Key (base64 string) into 8-bit unsigned integer array for the crypto key
	$signature = $hmacsha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stringToSign))	# Pass the signing string as UTF8 byte array (not base64)
																							# Generates the signature as base64 array

	# Format signature response 
	$signature = [Convert]::ToBase64String($signature)										# Convert base64 array to base64 string (which Verint API expects)
	$signature = $signature.Replace('+', '-').Replace('/', '_').Replace('=', '')			# Replace 'back' characters from base64 and remove padding (trim =)

		
    $verintAuthId = "Vrnt-1-HMAC-SHA256"

    $authHeaderValue = "$($verintAuthId) salt=$($salt),iat=$($issuedAt),kid=$($APIKeyId),sig=$($signature)"
    return $authHeaderValue
}


$HEADERS = @{
    'Authorization' = getAuthHeader $URL $method $APIkey
}

$HEADERS

$response = Invoke-RestMethod -Uri $URL -Method $method -Headers $HEADERS | ConvertTo-Json -Depth 10 | Out-File -FilePath "$($empID).json"


