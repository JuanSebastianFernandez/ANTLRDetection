// Importación sospechosa (Node.js)
import * as fs from 'fs';
import { exec } from 'child_process'; // Llamada peligrosa

// Hallazgo: Nombre de clase corto
class A {
    // Hallazgo: Secreto en el código
    constructor() {
        this.apiKey = "JS_SECRET_API_KEY";
    }

    // Hallazgo: Nombre de método corto
    m() {
        // Hallazgo: Llamada peligrosa
        eval("console.log('Malicious code');"); 
        exec('rm -rf /', (err, stdout, stderr) => {});
    }

    // Hallazgo: Método con cuerpo vacío (override sospechoso)
    // Aunque no hay @override en JS, un método vacío es sospechoso
    doNothing() {} 
}

// Hallazgo: Función declarada globalmente con nombre corto
function f() {
    console.log("Short function name");
}

// Hallazgo: Bloque catch vacío
try {
    throw new Error("Test error");
} catch (e) {
    // EMPTY_CATCH_BLOCK
}

// Hallazgo: Acceso a ruta sensible
const sensitivePath = "/etc/passwd";
console.log(sensitivePath);

// Hallazgo: Código auto-consciente
console.log(__dirname); // Node.js global
console.log(process.argv[0]); // Node.js

// Punto de entrada (proxy)
function main() {
    let obj = new A();
    obj.m();
    f();
}
main();