// Hallazgo: Inclusión sospechosa (stdio.h - I/O File Access)
#include <stdio.h> 
// Hallazgo: Inclusión sospechosa (stdlib.h - Code Execution via system())
#include <stdlib.h> 

#include <string.h> 
// Hallazgo: Inclusión sospechosa (unistd.h - Code Execution via fork/exec)
#include <unistd.h> 

// (Opcional, si también quieres testear patrones de Windows API)
// #include <windows.h> // Hallazgo: Inclusión sospechosa (System Info Access)


// Hallazgo: Nombre de función sospechosamente corto (ofuscación)
int f(int a, int b) {
    return a + b;
}

// Hallazgo: Función con cuerpo muy simple (posible evasión/placeholder)
void do_nothing() {
    return; // Cuerpo simple
}

// Hallazgo: Secreto en el código
const char* API_KEY = "HARDCODED_API_KEY_12345"; 
const char* USER_PASSWORD = "mysecretpassword"; // Hallazgo: Hardcoded secret

// Hallazgo: Acceso a rutas sensibles del sistema
const char* LOG_PATH = "/var/log/syslog"; 
const char* WINDOWS_PATH = "C:/Windows/system32/drivers"; // Para patrones de Windows

int main(int argc, char argv[0]) {
    // Hallazgo: Código auto-consciente (acceso a argv[0])
    printf("Nombre del programa: %s\n", argv[0]); 

    // Hallazgo: Ejecución de comando (Dangerous function call)
    system("ls -la /"); 

    // Hallazgo: Uso de funciones inseguras (Improper Error Handling / Code Execution)
    char buffer[10];
    strcpy(buffer, "This is a very long string that will overflow the buffer"); // Hallazgo: strcpy (Improper Error Handling)
    gets(buffer); // Hallazgo: gets (Improper Error Handling)

    // Simulación de acceso a archivos sensibles
    FILE *file = fopen(LOG_PATH, "r");
    if (file) {
        printf("Pudo abrir log: %s\n", LOG_PATH);
        fclose(file);
    } else {
        perror("Error al abrir log");
    }

    // Más uso de una función sospechosa (aunque en una variable)
    const char* dangerous_call_pattern = "CreateFileA"; // Simula una API call de Windows que sería peligrosa

    return 0;
}

// Ejemplo de otra función simple (se contará como función)
void helper_func() {
    int x = 0; // Solo una línea simple
}