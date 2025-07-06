#include <iostream> // Import sospechoso (IO)
#include <fstream>  // Import sospechoso (File IO)
#include <windows.h> // Import sospechoso (System Info Access)
#include <string.h>

// Hallazgo: Nombre de clase corto
class A {
public:
    // Hallazgo: Secreto en el código
    std::string password = "my_hardcoded_password"; 

    // Hallazgo: Nombre de función corto
    void x() {
        std::cout << "Hello" << std::endl;
    }

    // Hallazgo: Método sobreescrito con cuerpo simple (simulación)
    virtual void overrideMe() override {
        return;
    }
};

// Hallazgo: Función con cuerpo vacío
void empty_func() {
    //
}
// Hallazgo: Función con cuerpo solo return
void empty_func1() {
    return;
}

void empty_func2() {
    strcpy("executable", "file.exe"); // Hallazgo: Uso de strcpy (Buffer Overflow)
    return;
}
int main(int argc, char* argv[]) {
    // Hallazgo: Código auto-consciente (argv[0])
    std::cout << "Program name: " << argv[0] << std::endl;

    // Hallazgo: Llamada peligrosa (Code Execution)
    system("calc.exe"); 
    char inicial = 'A'; //prueba de detección de char
    char buffer[10];

    const wchar_t* mensaje = L"Hola mundo en wchar_t";

    // Hallazgo: Acceso a ruta sensible
    const char* sensitivePath = "/etc/shadow"; 
    std::cout << sensitivePath << std::endl;

    // Hallazgo: Uso de API de Windows peligrosa
    // CreateFileA("C:\\malware.log", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); // FILE_SYSTEM_ACCESS
    // VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // CODE_EXECUTION

    try {
        // Some risky operation
    } catch (...) { // Hallazgo: Empty catch block
        // Empty
    }

    // Hallazgo: Código auto-consciente (__FILE__)
    std::cout << __FILE__ << std::endl;

    return 0;
}