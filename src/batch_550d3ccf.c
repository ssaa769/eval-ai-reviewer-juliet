/*
 * Juliet Test Suite - Batch File
 * Batch #2 - Contains 30 test cases
 * This file contains multiple test functions for AI code review evaluation
 */

#include "std_testcase.h"

/* ==================== TEST CASES ==================== */

/* ----- Case 1: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_large_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_large_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE129_large_81_bad::action(int data) const
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 2: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_large_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_large_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE129_large_82_bad::action(int data)
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 3: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83_bad::process_buffer(int dataCopy)
{
    data = dataCopy;
    /* Issue */
    data = 10;
}

CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83_bad::~handle_payload()
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}
}


/* ---------------------------------------- */

/* ----- Case 4: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_large_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_large_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE129_large_84_bad::process_buffer(int dataCopy)
{
    data = dataCopy;
    /* Issue */
    data = 10;
}

CWE121_Stack_Based_Buffer_Overflow__CWE129_large_84_bad::~handle_payload()
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}
}


/* ---------------------------------------- */

/* ----- Case 5: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_81_bad::action(int data) const
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 6: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_82_bad::action(int data)
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 7: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_83.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32") /* include ws2_32.lib when linking */
#define CLOSE_SOCKET closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define SOCKET int
#endif

#define TCP_PORT 27015
#define LISTEN_BACKLOG 5
#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_83_bad::process_buffer(int dataCopy)
{
    data = dataCopy;
    {
#ifdef _WIN32
        WSADATA wsaData;
        int wsaDataInit = 0;
#endif
        int recvResult;
        struct sockaddr_in service;
        SOCKET listenSocket = INVALID_SOCKET;
        SOCKET acceptSocket = INVALID_SOCKET;
        char inputBuffer[CHAR_ARRAY_SIZE];
        do
        {
#ifdef _WIN32
            if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
            {
                break;
            }
            wsaDataInit = 1;
#endif
            /* Issue */
            listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listenSocket == INVALID_SOCKET)
            {
                break;
            }
            memset(&service, 0, sizeof(service));
            service.sin_family = AF_INET;
            service.sin_addr.s_addr = INADDR_ANY;
            service.sin_port = htons(TCP_PORT);
            if (::bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR)
            {
                break;
            }
            if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR)
            {
                break;
            }
            acceptSocket = accept(listenSocket, NULL, NULL);
            if (acceptSocket == SOCKET_ERROR)
            {
                break;
            }
            /* Abort on error or the connection was closed */
            recvResult = recv(acceptSocket, inputBuffer, CHAR_ARRAY_SIZE - 1, 0);
            if (recvResult == SOCKET_ERROR || recvResult == 0)
            {
                break;
            }
            /* NUL-terminate the string */
            inputBuffer[recvResult] = '\0';
            /* Convert to int */
            data = atoi(inputBuffer);
        }
        while (0);
        if (listenSocket != INVALID_SOCKET)
        {
            CLOSE_SOCKET(listenSocket);
        }
        if (acceptSocket != INVALID_SOCKET)
        {
            CLOSE_SOCKET(acceptSocket);
        }
#ifdef _WIN32
        if (wsaDataInit)
        {
            WSACleanup();
        }
#endif
    }
}

CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_83_bad::~handle_payload()
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}
}


/* ---------------------------------------- */

/* ----- Case 8: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_84.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32") /* include ws2_32.lib when linking */
#define CLOSE_SOCKET closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define SOCKET int
#endif

#define TCP_PORT 27015
#define LISTEN_BACKLOG 5
#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_84_bad::process_buffer(int dataCopy)
{
    data = dataCopy;
    {
#ifdef _WIN32
        WSADATA wsaData;
        int wsaDataInit = 0;
#endif
        int recvResult;
        struct sockaddr_in service;
        SOCKET listenSocket = INVALID_SOCKET;
        SOCKET acceptSocket = INVALID_SOCKET;
        char inputBuffer[CHAR_ARRAY_SIZE];
        do
        {
#ifdef _WIN32
            if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
            {
                break;
            }
            wsaDataInit = 1;
#endif
            /* Issue */
            listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listenSocket == INVALID_SOCKET)
            {
                break;
            }
            memset(&service, 0, sizeof(service));
            service.sin_family = AF_INET;
            service.sin_addr.s_addr = INADDR_ANY;
            service.sin_port = htons(TCP_PORT);
            if (::bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR)
            {
                break;
            }
            if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR)
            {
                break;
            }
            acceptSocket = accept(listenSocket, NULL, NULL);
            if (acceptSocket == SOCKET_ERROR)
            {
                break;
            }
            /* Abort on error or the connection was closed */
            recvResult = recv(acceptSocket, inputBuffer, CHAR_ARRAY_SIZE - 1, 0);
            if (recvResult == SOCKET_ERROR || recvResult == 0)
            {
                break;
            }
            /* NUL-terminate the string */
            inputBuffer[recvResult] = '\0';
            /* Convert to int */
            data = atoi(inputBuffer);
        }
        while (0);
        if (listenSocket != INVALID_SOCKET)
        {
            CLOSE_SOCKET(listenSocket);
        }
        if (acceptSocket != INVALID_SOCKET)
        {
            CLOSE_SOCKET(acceptSocket);
        }
#ifdef _WIN32
        if (wsaDataInit)
        {
            WSACleanup();
        }
#endif
    }
}

CWE121_Stack_Based_Buffer_Overflow__CWE129_listen_socket_84_bad::~handle_payload()
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}
}


/* ---------------------------------------- */

/* ----- Case 9: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_81_bad::action(int data) const
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 10: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_82_bad::action(int data)
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 11: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_83_bad::process_buffer(int dataCopy)
{
    data = dataCopy;
    /* Issue */
    data = RAND32();
}

CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_83_bad::~handle_payload()
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}
}


/* ---------------------------------------- */

/* ----- Case 12: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_84_bad::process_buffer(int dataCopy)
{
    data = dataCopy;
    /* Issue */
    data = RAND32();
}

CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_84_bad::~handle_payload()
{
    {
        int i;
        int buffer[10] = { 0 };
        /* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}
}


/* ---------------------------------------- */

/* ----- Case 13: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_81_bad::action(int * data) const
{
    {
        int source[10] = {0};
        size_t i;
        /* Issue */
        for (i = 0; i < 10; i++)
        {
            data[i] = source[i];
        }
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 14: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_82_bad::action(int * data)
{
    {
        int source[10] = {0};
        size_t i;
        /* Issue */
        for (i = 0; i < 10; i++)
        {
            data[i] = source[i];
        }
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 15: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_81_bad::action(int * data) const
{
    {
        int source[10] = {0};
        /* Issue */
        memcpy(data, source, 10*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 16: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_82_bad::action(int * data)
{
    {
        int source[10] = {0};
        /* Issue */
        memcpy(data, source, 10*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 17: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_81_bad::action(int * data) const
{
    {
        int source[10] = {0};
        /* Issue */
        memmove(data, source, 10*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 18: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_82_bad::action(int * data)
{
    {
        int source[10] = {0};
        /* Issue */
        memmove(data, source, 10*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 19: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE135_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE135_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE135_81_bad::action(void * data) const
{
    {
        /* POTENTIAL FLAW: treating pointer as a char* when it may point to a wide string */
        size_t dataLen = strlen((char *)data);
        void * dest = (void *)ALLOCA((dataLen+1) * sizeof(wchar_t));
        (void)wcscpy((wchar_t *)dest, (wchar_t *)data);
        printLine((char *)dest);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 20: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE135_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE135_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE135_82_bad::action(void * data)
{
    {
        /* POTENTIAL FLAW: treating pointer as a char* when it may point to a wide string */
        size_t dataLen = strlen((char *)data);
        void * dest = (void *)ALLOCA((dataLen+1) * sizeof(wchar_t));
        (void)wcscpy((wchar_t *)dest, (wchar_t *)data);
        printLine((char *)dest);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 21: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE135_83.h"

#define WIDE_STRING L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define CHAR_STRING "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE135_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE135_83_bad::CWE121_Stack_Based_Buffer_Overflow__CWE135_83_bad(void * dataCopy)
{
    data = dataCopy;
    /* Issue */
    data = (void *)WIDE_STRING;
}

CWE121_Stack_Based_Buffer_Overflow__CWE135_83_bad::~CWE121_Stack_Based_Buffer_Overflow__CWE135_83_bad()
{
    {
        /* POTENTIAL FLAW: treating pointer as a char* when it may point to a wide string */
        size_t dataLen = strlen((char *)data);
        void * dest = (void *)ALLOCA((dataLen+1) * sizeof(wchar_t));
        (void)wcscpy((wchar_t *)dest, (wchar_t *)data);
        printLine((char *)dest);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 22: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE135_84.h"

#define WIDE_STRING L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define CHAR_STRING "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE135_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE135_84_bad::CWE121_Stack_Based_Buffer_Overflow__CWE135_84_bad(void * dataCopy)
{
    data = dataCopy;
    /* Issue */
    data = (void *)WIDE_STRING;
}

CWE121_Stack_Based_Buffer_Overflow__CWE135_84_bad::~CWE121_Stack_Based_Buffer_Overflow__CWE135_84_bad()
{
    {
        /* POTENTIAL FLAW: treating pointer as a char* when it may point to a wide string */
        size_t dataLen = strlen((char *)data);
        void * dest = (void *)ALLOCA((dataLen+1) * sizeof(wchar_t));
        (void)wcscpy((wchar_t *)dest, (wchar_t *)data);
        printLine((char *)dest);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 23: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_81_bad::action(char * data) const
{
    {
        char source[10+1] = SRC_STRING;
        /* Issue */
        strcpy(data, source);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 24: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_82_bad::action(char * data)
{
    {
        char source[10+1] = SRC_STRING;
        /* Issue */
        strcpy(data, source);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 25: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_loop_81_bad::action(char * data) const
{
    {
        char source[10+1] = SRC_STRING;
        size_t i, sourceLen;
        sourceLen = strlen(source);
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 26: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_loop_82_bad::action(char * data)
{
    {
        char source[10+1] = SRC_STRING;
        size_t i, sourceLen;
        sourceLen = strlen(source);
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 27: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memcpy_81_bad::action(char * data) const
{
    {
        char source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memcpy(data, source, (strlen(source) + 1) * sizeof(char));
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 28: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memcpy_82_bad::action(char * data)
{
    {
        char source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memcpy(data, source, (strlen(source) + 1) * sizeof(char));
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 29: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memmove_81_bad::action(char * data) const
{
    {
        char source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memmove(data, source, (strlen(source) + 1) * sizeof(char));
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 30: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memmove_82_bad::action(char * data)
{
    {
        char source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memmove(data, source, (strlen(source) + 1) * sizeof(char));
        printLine(data);
    }
}

}


/* ---------------------------------------- */
