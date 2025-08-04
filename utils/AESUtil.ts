import CryptoJS from 'crypto-js';

/**
 * AES Utility class implementing AES-CBC encryption with PBKDF2 key derivation
 * Following Java cryptography patterns for consistency
 */
export class AESUtil {
  //private static readonly ALGORITHM = 'AES';
  private static readonly KEY_SIZE = 256; // bits
  private static readonly IV_SIZE = 16; // bytes
  private static readonly SALT_SIZE = 16; // bytes
  private static readonly ITERATION_COUNT = 100000;

  /**
   * Encrypts data using AES-CBC with PBKDF2 key derivation
   * @param data - The data to encrypt (as base64 string for images)
   * @param password - The password for encryption
   * @returns Encrypted data as base64 string with salt and IV prepended
   */
  static encrypt(data: string, password: string): string {
    try {
      // Generate random salt and IV
      const salt = CryptoJS.lib.WordArray.random(this.SALT_SIZE);
      const iv = CryptoJS.lib.WordArray.random(this.IV_SIZE);
      
      // Derive key from password using PBKDF2
      const key = CryptoJS.PBKDF2(password, salt, {
        keySize: this.KEY_SIZE / 32, // Convert bits to words (32 bits per word)
        iterations: this.ITERATION_COUNT,
        hasher: CryptoJS.algo.SHA256
      });
      
      // Encrypt the data
      const encrypted = CryptoJS.AES.encrypt(data, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });
      
      // Combine salt + IV + encrypted data
      const combined = salt.concat(iv).concat(encrypted.ciphertext);
      
      return CryptoJS.enc.Base64.stringify(combined);
    } catch (error) {
      throw new Error('Encryption failed: ' + (error as Error).message);
    }
  }

  /**
   * Decrypts data using AES-CBC with PBKDF2 key derivation
   * @param encryptedData - The encrypted data as base64 string
   * @param password - The password for decryption
   * @returns Decrypted data as string
   */
  static decrypt(encryptedData: string, password: string): string {
    try {
      // Parse the encrypted data
      const combined = CryptoJS.enc.Base64.parse(encryptedData);
      
      // Extract salt, IV, and ciphertext
      const salt = CryptoJS.lib.WordArray.create(combined.words.slice(0, this.SALT_SIZE / 4));
      const iv = CryptoJS.lib.WordArray.create(combined.words.slice(this.SALT_SIZE / 4, (this.SALT_SIZE + this.IV_SIZE) / 4));
      const ciphertext = CryptoJS.lib.WordArray.create(combined.words.slice((this.SALT_SIZE + this.IV_SIZE) / 4));
      
      // Derive key from password using the same salt
      const key = CryptoJS.PBKDF2(password, salt, {
        keySize: this.KEY_SIZE / 32,
        iterations: this.ITERATION_COUNT,
        hasher: CryptoJS.algo.SHA256
      });
      
      // Decrypt the data
      const decrypted = CryptoJS.AES.decrypt(
        CryptoJS.lib.CipherParams.create({ ciphertext: ciphertext }),
        key,
        {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        }
      );
      
      return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      throw new Error('Decryption failed: Invalid password or corrupted data');
    }
  }

  /**
   * Converts a File to base64 string
   * @param file - The file to convert
   * @returns Promise resolving to base64 string
   */
  static fileToBase64(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result as string;
        // Remove the data URL prefix (e.g., "data:image/jpeg;base64,")
        const base64 = result.split(',')[1];
        resolve(base64);
      };
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsDataURL(file);
    });
  }

  /**
   * Creates a downloadable text file with encrypted data
   * @param encryptedData - The encrypted data
   * @param filename - The filename for download
   */
  static downloadEncryptedFile(encryptedData: string, filename: string): void {
    const blob = new Blob([encryptedData], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}