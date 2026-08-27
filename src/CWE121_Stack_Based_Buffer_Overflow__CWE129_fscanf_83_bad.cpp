#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_fscanf_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_fscanf_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE129_fscanf_83_bad::process_buffer(int dataCopy)
{
    data = dataCopy;
    /* Issue */
    fscanf(stdin, "%d", &data);
}

CWE121_Stack_Based_Buffer_Overflow__CWE129_fscanf_83_bad::~handle_payload()
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
