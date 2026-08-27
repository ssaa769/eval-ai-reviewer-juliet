#include "std_testcase.h"
#include "std_testcase.h"
class BadClass 
{
    public:
        BadClass() 
        {
            name = NULL;
        }
    
        BadClass(const char * name)
        {
            if (name)
            {
                this->name = new char[strlen(name) + 1];
                strcpy(this->name, name);
            } 
            else 
            {
                this->name = new char[1];
                *(this->name) = '\0';
            }
        }

        ~BadClass()
        {
            delete [] name;
        }

        /* copy constructor is only here to avoid double free incidentals */
        BadClass(BadClass &badClassObject)
        { 
            this->name = new char[strlen(badClassObject.name)+1]; 
            strcpy(this->name, badClassObject.name);
        }
        
        BadClass& operator=(const BadClass& badClassObject) 
        {
            /* No check for self-assignment */
            delete [] this->name;
            this->name = new char[strlen(badClassObject.name)+1]; 
            strcpy(this->name, badClassObject.name); /* FLAW - if this is a self-assignment, 
                badClassObject.name has already been deleted, so this is a use after free (CWE-416). */
            return *this;
        }
        
        char * name;
};

void bad()
{
    BadClass badClassObject("BadClass");
    badClassObject = badClassObject;
    printLine(badClassObject.name);
}

