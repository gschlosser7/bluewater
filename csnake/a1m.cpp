#include D3DXVec3Subtract(out, a, b)

int main()
{
    int len;

    for (int i = 1; i < len; i++){
        for (int j = 1; j<=1; j++)
    }
}
//code above prints right triangle shaped matrix. (x*x) + (y*y) = z*z 
/*
Thus, the formula to determine the magnitude of a vector (in two-dimensional space)
 v = (x, y) is: |v| =√(x2 + y2). 
 This formula is from the Pythagorean theorem to derive vector 
in three-dimensional space: V = (x, y, z) is: |V| = √(x2 + y2 + z2)
*/
/*

I needed to make 2 modifications to my current approach.

The first modification is the one pointed out by @Daniel Kleinstein. But only with that, I stil got an error: C2059: syntax error: 'string'. This error is due to extern "C" { guards that are only understood by C++ (reference: C2059 syntax error 'string' ? ). For a C source file, I needed to add __cplusplus ifdef.

I summarize the overall procedures that led me to the correct result (there may be some redundancies though).

    I want to call the following C file from Python.

//Filename: my_functions.c
#include <stdio.h>

int square(int i){
   return i * i;
}

    Create a C file using __declspec(dllexport) and __cplusplus ifdef.

//Filename: my_functions2.c
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif
    __declspec(dllexport) int square(int i);
#ifdef __cplusplus
}
#endif

__declspec(dllexport) int square(int i)
{
    return i * i;
}

    Create a 64-bit dll file my_functions2.dll by running the following commands on Command Prompt. You need to locate the cl.exe carefully on your computer.

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64

cl.exe /D_USRDL /D_WINDLL my_functions2.c /MT /link /DLL /OUT:my_functions2.dll /MACHINE:X64

    Call the my_functions2.dll from Python using ctypes. In this example, I test the function square and obtain a correct result.
*/

//  #Filename: call_my_functions2.py
//  import ctypes as ctypes 
//  my_functions = ctypes.CDLL("./my_functions2.dll")

//  print(type(my_functions))
//  print(my_functions.square(10))

//  print("Done")

/*  I get the following output:

<class 'ctypes.CDLL'>
100
Done

*/