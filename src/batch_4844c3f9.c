/*
 * Juliet Test Suite - Batch File
 * Batch #2 - Contains 50 test cases
 * This file contains multiple test functions for AI code review evaluation
 */

#include "std_testcase.h"

/* ==================== TEST CASES ==================== */

/* ----- Case 1: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_81_bad::action(char * data) const
{
    {
        char source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        strncpy(data, source, strlen(source) + 1);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 2: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_82_bad::action(char * data)
{
    {
        char source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        strncpy(data, source, strlen(source) + 1);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 3: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_cpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_cpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_cpy_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Issue */
        wcscpy(data, source);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 4: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_cpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_cpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_cpy_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Issue */
        wcscpy(data, source);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 5: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_loop_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[10+1] = SRC_STRING;
        size_t i, sourceLen;
        sourceLen = wcslen(source);
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 6: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_loop_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        size_t i, sourceLen;
        sourceLen = wcslen(source);
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 7: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memcpy_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memcpy(data, source, (wcslen(source) + 1) * sizeof(wchar_t));
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 8: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memcpy_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memcpy(data, source, (wcslen(source) + 1) * sizeof(wchar_t));
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 9: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memmove_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memmove(data, source, (wcslen(source) + 1) * sizeof(wchar_t));
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 10: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_memmove_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memmove(data, source, (wcslen(source) + 1) * sizeof(wchar_t));
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 11: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_ncpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_ncpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_ncpy_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        wcsncpy(data, source, wcslen(source) + 1);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 12: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_ncpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_ncpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_ncpy_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        wcsncpy(data, source, wcslen(source) + 1);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 13: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_cpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_cpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_cpy_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Issue */
        wcscpy(data, source);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 14: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_cpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_cpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_cpy_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Issue */
        wcscpy(data, source);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 15: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_loop_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[10+1] = SRC_STRING;
        size_t i, sourceLen;
        sourceLen = wcslen(source);
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 16: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_loop_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        size_t i, sourceLen;
        sourceLen = wcslen(source);
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 17: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memcpy_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memcpy(data, source, (wcslen(source) + 1) * sizeof(wchar_t));
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 18: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memcpy_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memcpy(data, source, (wcslen(source) + 1) * sizeof(wchar_t));
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 19: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memmove_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memmove(data, source, (wcslen(source) + 1) * sizeof(wchar_t));
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 20: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_memmove_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        memmove(data, source, (wcslen(source) + 1) * sizeof(wchar_t));
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 21: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_ncpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_ncpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_ncpy_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        wcsncpy(data, source, wcslen(source) + 1);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 22: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_ncpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_ncpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_ncpy_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* Copy length + 1 to include NUL terminator from source */
        /* Issue */
        wcsncpy(data, source, wcslen(source) + 1);
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 23: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_loop_81_bad::action(char * data) const
{
    {
        size_t i;
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        for (i = 0; i < 100; i++)
        {
            data[i] = source[i];
        }
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 24: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_loop_82_bad::action(char * data)
{
    {
        size_t i;
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        for (i = 0; i < 100; i++)
        {
            data[i] = source[i];
        }
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 25: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memcpy_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        memcpy(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 26: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memcpy_82_bad::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        memcpy(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 27: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memmove_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        memmove(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 28: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memmove_82_bad::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        memmove(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 29: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        strncat(data, source, 100);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 30: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_82_bad::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        strncat(data, source, 100);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 31: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncpy_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        strncpy(data, source, 100-1);
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 32: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncpy_82_bad::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        strncpy(data, source, 100-1);
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 33: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_snprintf_81.h"

#ifdef _WIN32
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_snprintf_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_snprintf_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        SNPRINTF(data, 100, "%s", source);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 34: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_snprintf_82.h"

#ifdef _WIN32
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_snprintf_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_snprintf_82_bad::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        SNPRINTF(data, 100, "%s", source);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 35: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_loop_81_bad::action(char * data) const
{
    {
        size_t i;
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        for (i = 0; i < 100; i++)
        {
            data[i] = source[i];
        }
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 36: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_loop_82_bad::action(char * data)
{
    {
        size_t i;
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        for (i = 0; i < 100; i++)
        {
            data[i] = source[i];
        }
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 37: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        memcpy(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 38: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_82_bad::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        memcpy(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 39: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        memmove(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 40: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memmove_82_bad::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        memmove(data, source, 100*sizeof(char));
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 41: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        strncat(data, source, 100);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 42: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_82_bad::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        strncat(data, source, 100);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 43: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncpy_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        strncpy(data, source, 100-1);
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 44: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncpy_82_bad::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        strncpy(data, source, 100-1);
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 45: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_snprintf_81.h"

#ifdef _WIN32
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_snprintf_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_snprintf_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        SNPRINTF(data, 100, "%s", source);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 46: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_snprintf_82.h"

#ifdef _WIN32
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_snprintf_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_snprintf_82_bad::action(char * data)
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* Issue */
        SNPRINTF(data, 100, "%s", source);
        printLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 47: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_loop_81_bad::action(int64_t * data) const
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        {
            size_t i;
            /* Issue */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printLongLongLine(data[0]);
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 48: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_loop_82_bad::action(int64_t * data)
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        {
            size_t i;
            /* Issue */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printLongLongLine(data[0]);
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 49: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_81_bad::action(int64_t * data) const
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        /* Issue */
        memcpy(data, source, 100*sizeof(int64_t));
        printLongLongLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 50: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_82_bad::action(int64_t * data)
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        /* Issue */
        memcpy(data, source, 100*sizeof(int64_t));
        printLongLongLine(data[0]);
    }
}

}


/* ---------------------------------------- */
