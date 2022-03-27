#include <iostream>
#include <string>

#include "utils.h"

using namespace std;

int main(int argc, char *argv[])
{
    int count;

    // Display each command-line argument.
    cout << "\nCommand-line arguments:\n";
    for( count = 0; count < argc; count++ )
         cout << "  argv[" << count << "]   " << argv[count] << "\n";

    cout << "Hello world\n";

    return 0;
}

