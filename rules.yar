rule GenericMalware
{
    meta:
        description = "Detects Generic Malware Based On Suspicious Strings And Behaviors"
        author = "Stallone"
        date = "2025-03-17"
    
    strings:
        // Common malware keywords
        $cmd1 = "powershell -exec bypass"
        $cmd2 = "cmd.exe /c"
        $cmd3 = "taskkill /F /IM"
        $cmd4 = "schtasks /create /tn"
        $cmd5 = "net user /add"
        $cmd6 = "base64 -d"
        $cmd7 = "ROT13"
        $cmd8 = "XOR encoded"
        $cmd9 = "keystroke logger"
        $cmd10 = "reverse shell"
        
        // Suspicious file extensions
        $ext1 = ".exe"
        $ext2 = ".dll"
        $ext3 = ".bat"
        $ext4 = ".vbs"
        $ext5 = ".ps1"
        
    condition:
        any of ($cmd*) or any of ($ext*)
}

rule RansomwareDetection
{
    meta:
        description = "Detects potential ransomware encryption patterns"
        author = "Stallone"
        date = "2025-03-17"
    
    strings:
        $enc1 = "AES_encrypt"
        $enc2 = "RSA_public_encrypt"
        $enc3 = "CryptEncrypt"
        $enc4 = "EncryptFile"
        $enc5 = "ransom note"
        $enc6 = "decrypt instructions"
        $enc7 = "bitcoin address"
        $enc8 = "TOR hidden service"

    condition:
        any of ($enc*)
}

rule KeyloggerDetection
{
    meta:
        description = "Detects common keylogger patterns"
        author = "Stallone"
        date = "2025-03-17"
    
    strings:
        $key1 = "GetAsyncKeyState"
        $key2 = "keylogging module"
        $key3 = "capture keystrokes"
        $key4 = "password dump"
        $key5 = "clipboard data"
        $key6 = "log.txt"
    
    condition:
        any of ($key*)
}

rule ObfuscatedScripts
{
    meta:
        description = "Detects obfuscated scripts using Base64, XOR, and ROT13 encoding"
        author = "Stallone"
        date = "2025-03-17"
    
    strings:
        $b64_1 = "base64 -d"
        $b64_2 = "echo .* | base64 -d"
        $xor_1 = "XOR"
        $rot13_1 = "ROT13"
        $ps1_1 = "powershell.exe -nop -w hidden"
    
    condition:
        any of ($b64_*) or any of ($xor_*) or any of ($rot13_*) or any of ($ps1_*)
}

rule SuspiciousNetworkActivity
{
    meta:
        description = "Detects suspicious network activity like C2 servers, reverse shells, and exfiltration"
        author = "Stallone"
        date = "2025-03-17"
    
    strings:
        $net1 = "nc -e /bin/sh"
        $net2 = "ncat -e"
        $net3 = "Invoke-WebRequest"
        $net4 = "curl -o"
        $net5 = "wget http"
        $net6 = "data exfiltration"
        $net7 = "C2 server"

    condition:
        any of ($net*)
}

rule RootkitDetection
{
    meta:
        description = "Detects rootkits that modify system processes"
        author = "Stallone"
        date = "2025-03-17"
    
    strings:
        $root1 = "hide process"
        $root2 = "system call hooking"
        $root3 = "ring0 access"
        $root4 = "direct kernel object manipulation"
    
    condition:
        any of ($root*)
}
