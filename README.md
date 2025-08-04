# Snap Crypt - Client-Side Image Encryption

A secure image encryption/decryption web application that runs entirely in your browser using AES-CBC with PBKDF2 key derivation. No backend server required — all encryption happens client-side.

## Features

- **Client-Side Security**: All encryption/decryption happens in your browser — no data leaves your device
- **Strong Encryption**: AES-256-CBC with PBKDF2 key derivation (100,000 iterations)
- **Password Protection**: Images can only be decrypted with the correct password
- **Security Measures**: File access blocked after 3 failed decryption attempts
- **No Database**: Uses browser localStorage for attempt tracking
- **Modern UI**: React frontend with Tailwind CSS and glassmorphism design
- **Java-Style Implementation**: Cryptography patterns following Java standards

## How It Works

### Encryption Process
1. Select an image file and enter a password
2. Image is converted to base64 format
3. Random salt and IV are generated
4. Password is derived using PBKDF2 with 100,000 iterations
5. Image data is encrypted using AES-256-CBC
6. Encrypted data (salt + IV + ciphertext) is saved as a text file

### Decryption Process
1. Upload the encrypted text file and enter the password
2. Extract salt, IV, and ciphertext from the file
3. Derive the key using the same password and salt
4. Decrypt the data using AES-256-CBC
5. Display the original image

### Security Features
- **PBKDF2 Key Derivation**: 100,000 iterations with SHA-256
- **Random Salt & IV**: Each encryption uses unique random values
- **Failed Attempt Protection**: Access blocked after 3 incorrect passwords
- **Client-Side Only**: No server communication — complete privacy

## Getting Started

### Prerequisites
- Node.js 16 or higher
- npm or yarn

### Installation & Running

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Start Development Server**:
   ```bash
   npm run dev
   ```

3. **Open in Browser**:
   Navigate to http://localhost:5173

## Usage

### Encrypting an Image
1. Click the "Encrypt" tab
2. Upload an image file (JPG, PNG, etc.)
3. Enter a strong password (minimum 8 characters)
4. Click "Encrypt & Download"
5. Save the generated `.txt` file containing encrypted data

### Decrypting an Image
1. Click the "Decrypt" tab
2. Upload a previously encrypted `.txt` file
3. Enter the correct password
4. Click "Decrypt Image"
5. View and optionally download the decrypted image

## Security Considerations

- **Password Strength**: Use strong passwords with mixed case, numbers, and symbols
- **File Storage**: Keep encrypted files secure and backed up
- **Attempt Limits**: Files become inaccessible after 3 failed password attempts
- **Browser Storage**: Failed attempts are tracked in localStorage
- **Privacy**: All operations happen locally - no data transmission

## Technical Implementation

### Cryptography Stack
- **Encryption**: AES-256 in CBC mode
- **Key Derivation**: PBKDF2 with SHA-256 hash
- **Iterations**: 100,000 for key derivation
- **Random Generation**: Cryptographically secure random salt and IV
- **Library**: CryptoJS for JavaScript cryptography

### Architecture
- **Frontend**: React 18 with TypeScript
- **Styling**: Tailwind CSS with custom gradients
- **Icons**: Lucide React
- **Build Tool**: Vite
- **Security**: Client-side only, no backend dependencies

### File Structure
```
src/
├── utils/
│   ├── AESUtil.ts          # Core encryption/decryption logic
│   └── SecurityManager.ts  # Failed attempt tracking
├── App.tsx                 # Main application component
├── index.css              # Tailwind CSS imports
└── main.tsx               # Application entry point
```

## Security Features Explained

### AES-CBC Encryption
- Uses 256-bit keys for maximum security
- CBC mode provides semantic security
- Each encryption uses a unique IV

### PBKDF2 Key Derivation
- Derives encryption keys from passwords
- 100,000 iterations prevent brute force attacks
- SHA-256 hash function for security
- Random salt prevents rainbow table attacks

### Failed Attempt Protection
- Tracks failed decryption attempts per file
- Blocks access after 3 failed attempts
- Uses file content hash for tracking
- Stored in browser localStorage

## Browser Compatibility

- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+

Requires modern browser with Web Crypto API support.

## License

This project is for educational and personal use. Ensure compliance with local encryption laws and regulations.

## Disclaimer

This is a demonstration of client-side encryption techniques. For production use, consider additional security measures and professional security auditing.