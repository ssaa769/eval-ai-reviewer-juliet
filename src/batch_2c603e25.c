/*
 * Juliet Test Suite - Batch File
 * Batch #4 - Contains 50 test cases
 * This file contains multiple test functions for AI code review evaluation
 */

#include "std_testcase.h"

/* ==================== TEST CASES ==================== */

/* ----- Case 1: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncat_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncat_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncat_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        wcsncat(data, source, 100);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 2: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncat_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncat_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncat_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        wcsncat(data, source, 100);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 3: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncpy_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        wcsncpy(data, source, 100-1);
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 4: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_ncpy_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        wcsncpy(data, source, 100-1);
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 5: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_snprintf_81.h"

#ifdef _WIN32
#define SNPRINTF _snwprintf
#else
#define SNPRINTF swprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_snprintf_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_snprintf_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        SNPRINTF(data, 100, L"%s", source);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 6: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_snprintf_82.h"

#ifdef _WIN32
#define SNPRINTF _snwprintf
#else
#define SNPRINTF swprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_snprintf_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_snprintf_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        SNPRINTF(data, 100, L"%s", source);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 7: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        size_t i, dataLen;
        dataLen = strlen(data);
        /* Issue */
        for (i = 0; i < dataLen; i++)
        {
            dest[i] = data[i];
        }
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 8: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        size_t i, dataLen;
        dataLen = strlen(data);
        /* Issue */
        for (i = 0; i < dataLen; i++)
        {
            dest[i] = data[i];
        }
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 9: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        size_t i, dataLen;
        dataLen = strlen(data);
        /* Issue */
        for (i = 0; i < dataLen; i++)
        {
            dest[i] = data[i];
        }
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 10: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_loop_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        size_t i, dataLen;
        dataLen = strlen(data);
        /* Issue */
        for (i = 0; i < dataLen; i++)
        {
            dest[i] = data[i];
        }
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 11: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        /* Issue */
        memcpy(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 12: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        /* Issue */
        memcpy(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 13: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        memcpy(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 14: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memcpy_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        memcpy(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 15: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        /* Issue */
        memmove(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 16: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        /* Issue */
        memmove(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 17: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        memmove(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 18: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_memmove_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        memmove(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 19: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        /* Issue */
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 20: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        /* Issue */
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 21: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 22: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 23: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        /* Issue */
        strncpy(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 24: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        /* Issue */
        strncpy(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 25: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        strncpy(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 26: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        strncpy(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 27: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_81.h"

#ifdef _WIN32
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        /* Issue */
        SNPRINTF(dest, strlen(data), "%s", data);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 28: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_82.h"

#ifdef _WIN32
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        /* Issue */
        SNPRINTF(dest, strlen(data), "%s", data);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 29: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_83.h"

#ifdef _WIN32
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        SNPRINTF(dest, strlen(data), "%s", data);
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 30: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_84.h"

#ifdef _WIN32
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_snprintf_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        SNPRINTF(dest, strlen(data), "%s", data);
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 31: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        size_t i, dataLen;
        dataLen = strlen(data);
        /* Issue */
        for (i = 0; i < dataLen; i++)
        {
            dest[i] = data[i];
        }
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 32: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        size_t i, dataLen;
        dataLen = strlen(data);
        /* Issue */
        for (i = 0; i < dataLen; i++)
        {
            dest[i] = data[i];
        }
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 33: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        size_t i, dataLen;
        dataLen = strlen(data);
        /* Issue */
        for (i = 0; i < dataLen; i++)
        {
            dest[i] = data[i];
        }
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 34: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_loop_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        size_t i, dataLen;
        dataLen = strlen(data);
        /* Issue */
        for (i = 0; i < dataLen; i++)
        {
            dest[i] = data[i];
        }
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 35: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        /* Issue */
        memcpy(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 36: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        /* Issue */
        memcpy(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 37: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        memcpy(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 38: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        memcpy(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 39: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        /* Issue */
        memmove(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 40: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        /* Issue */
        memmove(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 41: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        memmove(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 42: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memmove_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        memmove(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 43: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        /* Issue */
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 44: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        /* Issue */
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 45: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 46: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        strncat(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 47: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_81_bad::action(char * data) const
{
    {
        char dest[50] = "";
        /* Issue */
        strncpy(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 48: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_82_bad::action(char * data)
{
    {
        char dest[50] = "";
        /* Issue */
        strncpy(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 49: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_83_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_83_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        strncpy(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */

/* ----- Case 50: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_84.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_84
{
CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_84_bad::process_buffer(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncpy_84_bad::~handle_payload()
{
    {
        char dest[50] = "";
        /* Issue */
        strncpy(dest, data, strlen(data));
        dest[50-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}
}


/* ---------------------------------------- */
