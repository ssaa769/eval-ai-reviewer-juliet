/*
 * Juliet Test Suite - Batch File
 * Batch #3 - Contains 50 test cases
 * This file contains multiple test functions for AI code review evaluation
 */

#include "std_testcase.h"

/* ==================== TEST CASES ==================== */

/* ----- Case 1: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_81_bad::action(int64_t * data) const
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        /* Issue */
        memmove(data, source, 100*sizeof(int64_t));
        printLongLongLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 2: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_82_bad::action(int64_t * data)
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        /* Issue */
        memmove(data, source, 100*sizeof(int64_t));
        printLongLongLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 3: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_81_bad::action(int64_t * data) const
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

/* ----- Case 4: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_82_bad::action(int64_t * data)
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

/* ----- Case 5: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memcpy_81_bad::action(int64_t * data) const
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

/* ----- Case 6: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memcpy_82_bad::action(int64_t * data)
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

/* ----- Case 7: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81_bad::action(int64_t * data) const
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        /* Issue */
        memmove(data, source, 100*sizeof(int64_t));
        printLongLongLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 8: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_82_bad::action(int64_t * data)
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        /* Issue */
        memmove(data, source, 100*sizeof(int64_t));
        printLongLongLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 9: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_loop_81_bad::action(int * data) const
{
    {
        int source[100] = {0}; /* fill with 0's */
        {
            size_t i;
            /* Issue */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printIntLine(data[0]);
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 10: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_loop_82_bad::action(int * data)
{
    {
        int source[100] = {0}; /* fill with 0's */
        {
            size_t i;
            /* Issue */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printIntLine(data[0]);
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 11: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_81_bad::action(int * data) const
{
    {
        int source[100] = {0}; /* fill with 0's */
        /* Issue */
        memcpy(data, source, 100*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 12: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_82_bad::action(int * data)
{
    {
        int source[100] = {0}; /* fill with 0's */
        /* Issue */
        memcpy(data, source, 100*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 13: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memmove_81_bad::action(int * data) const
{
    {
        int source[100] = {0}; /* fill with 0's */
        /* Issue */
        memmove(data, source, 100*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 14: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memmove_82_bad::action(int * data)
{
    {
        int source[100] = {0}; /* fill with 0's */
        /* Issue */
        memmove(data, source, 100*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 15: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_loop_81_bad::action(int * data) const
{
    {
        int source[100] = {0}; /* fill with 0's */
        {
            size_t i;
            /* Issue */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printIntLine(data[0]);
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 16: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_loop_82_bad::action(int * data)
{
    {
        int source[100] = {0}; /* fill with 0's */
        {
            size_t i;
            /* Issue */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printIntLine(data[0]);
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 17: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy_81_bad::action(int * data) const
{
    {
        int source[100] = {0}; /* fill with 0's */
        /* Issue */
        memcpy(data, source, 100*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 18: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memcpy_82_bad::action(int * data)
{
    {
        int source[100] = {0}; /* fill with 0's */
        /* Issue */
        memcpy(data, source, 100*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 19: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_81_bad::action(int * data) const
{
    {
        int source[100] = {0}; /* fill with 0's */
        /* Issue */
        memmove(data, source, 100*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 20: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_82_bad::action(int * data)
{
    {
        int source[100] = {0}; /* fill with 0's */
        /* Issue */
        memmove(data, source, 100*sizeof(int));
        printIntLine(data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 21: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_loop_81_bad::action(twoIntsStruct * data) const
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        {
            size_t i;
            /* Issue */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printStructLine(&data[0]);
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 22: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_loop_82_bad::action(twoIntsStruct * data)
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        {
            size_t i;
            /* Issue */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printStructLine(&data[0]);
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 23: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_81_bad::action(twoIntsStruct * data) const
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        /* Issue */
        memcpy(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 24: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_82_bad::action(twoIntsStruct * data)
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        /* Issue */
        memcpy(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 25: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_81_bad::action(twoIntsStruct * data) const
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        /* Issue */
        memmove(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 26: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_82_bad::action(twoIntsStruct * data)
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        /* Issue */
        memmove(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 27: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_loop_81_bad::action(twoIntsStruct * data) const
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        {
            size_t i;
            /* Issue */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printStructLine(&data[0]);
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 28: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_loop_82_bad::action(twoIntsStruct * data)
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        {
            size_t i;
            /* Issue */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printStructLine(&data[0]);
        }
    }
}

}


/* ---------------------------------------- */

/* ----- Case 29: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_81_bad::action(twoIntsStruct * data) const
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        /* Issue */
        memcpy(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 30: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_82_bad::action(twoIntsStruct * data)
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        /* Issue */
        memcpy(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 31: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memmove_81_bad::action(twoIntsStruct * data) const
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        /* Issue */
        memmove(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 32: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memmove_82_bad::action(twoIntsStruct * data)
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        /* Issue */
        memmove(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 33: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_loop_81_bad::action(wchar_t * data) const
{
    {
        size_t i;
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        for (i = 0; i < 100; i++)
        {
            data[i] = source[i];
        }
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 34: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_loop_82_bad::action(wchar_t * data)
{
    {
        size_t i;
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        for (i = 0; i < 100; i++)
        {
            data[i] = source[i];
        }
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 35: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memcpy_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        memcpy(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 36: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memcpy_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        memcpy(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 37: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memmove_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        memmove(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 38: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_memmove_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        memmove(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 39: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncat_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncat_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncat_81_bad::action(wchar_t * data) const
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

/* ----- Case 40: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncat_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncat_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncat_82_bad::action(wchar_t * data)
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

/* ----- Case 41: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_81_bad::action(wchar_t * data) const
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

/* ----- Case 42: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_82_bad::action(wchar_t * data)
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

/* ----- Case 43: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_snprintf_81.h"

#ifdef _WIN32
#define SNPRINTF _snwprintf
#else
#define SNPRINTF swprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_snprintf_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_snprintf_81_bad::action(wchar_t * data) const
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

/* ----- Case 44: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_snprintf_82.h"

#ifdef _WIN32
#define SNPRINTF _snwprintf
#else
#define SNPRINTF swprintf
#endif

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_snprintf_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_snprintf_82_bad::action(wchar_t * data)
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

/* ----- Case 45: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_loop_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_loop_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_loop_81_bad::action(wchar_t * data) const
{
    {
        size_t i;
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        for (i = 0; i < 100; i++)
        {
            data[i] = source[i];
        }
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 46: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_loop_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_loop_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_loop_82_bad::action(wchar_t * data)
{
    {
        size_t i;
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        for (i = 0; i < 100; i++)
        {
            data[i] = source[i];
        }
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 47: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memcpy_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        memcpy(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 48: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memcpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memcpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memcpy_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        memcpy(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 49: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memmove_81_bad::action(wchar_t * data) const
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        memmove(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */

/* ----- Case 50: CWE-121 (bad) ----- */
#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memmove_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* Issue */
        memmove(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}


/* ---------------------------------------- */
