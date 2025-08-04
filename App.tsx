import React, { useState } from 'react';
import { Shield, Lock, Unlock, Upload, Download, AlertTriangle, Eye, EyeOff, FileText, Image as ImageIcon } from 'lucide-react';
import { AESUtil } from './utils/AESUtil';
import { SecurityManager } from './utils/SecurityManager';

function App() {
  const [mode, setMode] = useState<'encrypt' | 'decrypt'>('encrypt');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState<'success' | 'error' | 'warning'>('success');

  // Encrypt mode state
  const [selectedImage, setSelectedImage] = useState<File | null>(null);
  const [encryptPassword, setEncryptPassword] = useState('');
  const [showEncryptPassword, setShowEncryptPassword] = useState(false);

  // Decrypt mode state
  const [selectedTextFile, setSelectedTextFile] = useState<File | null>(null);
  const [decryptPassword, setDecryptPassword] = useState('');
  const [showDecryptPassword, setShowDecryptPassword] = useState(false);
  const [decryptedImage, setDecryptedImage] = useState<string | null>(null);

  const showMessage = (msg: string, type: 'success' | 'error' | 'warning' = 'success') => {
    setMessage(msg);
    setMessageType(type);
    setTimeout(() => setMessage(''), 5000);
  };

  const handleImageUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file && file.type.startsWith('image/')) {
      setSelectedImage(file);
    } else {
      showMessage('Please select a valid image file', 'error');
    }
  };

  const handleTextFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file && file.type === 'text/plain') {
      setSelectedTextFile(file);
    } else {
      showMessage('Please select a valid text file (.txt)', 'error');
    }
  };

  const handleEncrypt = async () => {
    if (!selectedImage || !encryptPassword) {
      showMessage('Please select an image and enter a password', 'error');
      return;
    }

    if (encryptPassword.length < 8) {
      showMessage('Password must be at least 8 characters long', 'error');
      return;
    }

    setLoading(true);
    try {
      // Convert image to base64
      const imageBase64 = await AESUtil.fileToBase64(selectedImage);
      
      // Encrypt the image data
      const encryptedData = AESUtil.encrypt(imageBase64, encryptPassword);
      
      // Generate filename
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `encrypted_${selectedImage.name.split('.')[0]}_${timestamp}.txt`;
      
      // Download the encrypted file
      AESUtil.downloadEncryptedFile(encryptedData, filename);
      
      showMessage('Image encrypted successfully! Download started.', 'success');
      setSelectedImage(null);
      setEncryptPassword('');
      
      // Reset file input
      const fileInput = document.getElementById('image-upload') as HTMLInputElement;
      if (fileInput) fileInput.value = '';
      
    } catch (error) {
      showMessage('Encryption failed: ' + (error as Error).message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!selectedTextFile || !decryptPassword) {
      showMessage('Please select an encrypted text file and enter the password', 'error');
      return;
    }

    setLoading(true);
    try {
      // Read the encrypted file
      const fileContent = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result as string);
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsText(selectedTextFile);
      });

      // Create file hash for tracking attempts
      const fileHash = SecurityManager.createFileHash(fileContent);
      
      // Check if file is blocked
      if (SecurityManager.isFileBlocked(fileHash)) {
        showMessage('File access denied due to too many failed attempts!', 'error');
        setSelectedTextFile(null);
        const fileInput = document.getElementById('text-upload') as HTMLInputElement;
        if (fileInput) fileInput.value = '';
        return;
      }

      try {
        // Attempt to decrypt
        const decryptedBase64 = AESUtil.decrypt(fileContent, decryptPassword);
        
        // Clear failed attempts on success
        SecurityManager.clearFailedAttempts(fileHash);
        
        // Display the decrypted image
        setDecryptedImage(decryptedBase64);
        showMessage('Image decrypted successfully!', 'success');
        setDecryptPassword('');
        
      } catch (decryptError) {
        // Record failed attempt
        const remainingAttempts = SecurityManager.recordFailedAttempt(fileHash);
        
        if (remainingAttempts === 0) {
          showMessage('Maximum attempts exceeded! File access blocked for security.', 'error');
          setSelectedTextFile(null);
          const fileInput = document.getElementById('text-upload') as HTMLInputElement;
          if (fileInput) fileInput.value = '';
        } else {
          showMessage(`Incorrect password. ${remainingAttempts} attempts remaining.`, 'warning');
        }
      }
      
    } catch (error) {
      showMessage('Failed to read encrypted file: ' + (error as Error).message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setSelectedImage(null);
    setSelectedTextFile(null);
    setEncryptPassword('');
    setDecryptPassword('');
    setDecryptedImage(null);
    setMessage('');
    
    // Reset file inputs
    const imageInput = document.getElementById('image-upload') as HTMLInputElement;
    const textInput = document.getElementById('text-upload') as HTMLInputElement;
    if (imageInput) imageInput.value = '';
    if (textInput) textInput.value = '';
  };

  const downloadDecryptedImage = () => {
    if (!decryptedImage) return;
    
    const link = document.createElement('a');
    link.href = `data:image/jpeg;base64,${decryptedImage}`;
    link.download = 'decrypted_image.jpg';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-800">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-blue-400 mr-3" />
            <h1 className="text-4xl font-bold text-white">Snap Crypt</h1>
          </div>
          <p className="text-slate-300 text-lg">Client-Side Image Encryption with AES-CBC & PBKDF2</p>
          <p className="text-slate-400 text-sm mt-2">All encryption happens in your browser - no data leaves your device</p>
        </div>

        {/* Mode Toggle */}
        <div className="flex justify-center mb-8">
          <div className="bg-white/10 backdrop-blur-sm rounded-xl p-1 flex">
            <button
              onClick={() => { setMode('encrypt'); resetForm(); }}
              className={`px-6 py-3 rounded-lg font-medium transition-all flex items-center ${
                mode === 'encrypt'
                  ? 'bg-blue-500 text-white shadow-lg'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              <Lock className="w-4 h-4 mr-2" />
              Encrypt
            </button>
            <button
              onClick={() => { setMode('decrypt'); resetForm(); }}
              className={`px-6 py-3 rounded-lg font-medium transition-all flex items-center ${
                mode === 'decrypt'
                  ? 'bg-teal-500 text-white shadow-lg'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              <Unlock className="w-4 h-4 mr-2" />
              Decrypt
            </button>
          </div>
        </div>

        {/* Message Display */}
        {message && (
          <div className={`mb-6 p-4 rounded-lg flex items-center max-w-2xl mx-auto ${
            messageType === 'success' ? 'bg-green-500/20 text-green-300 border border-green-500' :
            messageType === 'warning' ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500' :
            'bg-red-500/20 text-red-300 border border-red-500'
          }`}>
            <AlertTriangle className="w-5 h-5 mr-2 flex-shrink-0" />
            {message}
          </div>
        )}

        {/* Main Content */}
        <div className="max-w-2xl mx-auto">
          {mode === 'encrypt' ? (
            <div className="bg-white/10 backdrop-blur-sm rounded-2xl p-8 border border-white/20">
              <h2 className="text-2xl font-bold text-white mb-6 flex items-center">
                <Lock className="w-6 h-6 mr-2 text-blue-400" />
                Encrypt Image
              </h2>
              
              {/* Image Upload */}
              <div className="mb-6">
                <label className="block text-slate-300 mb-2">Select Image</label>
                <div className="relative">
                  <input
                    type="file"
                    accept="image/*"
                    onChange={handleImageUpload}
                    className="hidden"
                    id="image-upload"
                  />
                  <label
                    htmlFor="image-upload"
                    className="block w-full p-6 border-2 border-dashed border-slate-500 rounded-lg text-center cursor-pointer hover:border-blue-400 transition-colors bg-slate-800/50"
                  >
                    {selectedImage ? (
                      <div className="flex items-center justify-center">
                        <ImageIcon className="w-8 h-8 mr-2 text-blue-300" />
                        <span className="text-blue-300">{selectedImage.name}</span>
                      </div>
                    ) : (
                      <div>
                        <Upload className="w-8 h-8 mx-auto mb-2 text-slate-400" />
                        <span className="text-slate-400">Click to select an image</span>
                      </div>
                    )}
                  </label>
                </div>
              </div>

              {/* Password Input */}
              <div className="mb-6">
                <label className="block text-slate-300 mb-2">Encryption Password</label>
                <div className="relative">
                  <input
                    type={showEncryptPassword ? 'text' : 'password'}
                    value={encryptPassword}
                    onChange={(e) => setEncryptPassword(e.target.value)}
                    placeholder="Enter a strong password (min 8 characters)"
                    className="w-full px-4 py-3 pr-12 bg-slate-800/50 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:border-blue-400 focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowEncryptPassword(!showEncryptPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-white"
                  >
                    {showEncryptPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
                <p className="text-slate-400 text-xs mt-1">Use a strong password with mixed case, numbers, and symbols</p>
              </div>

              {/* Encrypt Button */}
              <button
                onClick={handleEncrypt}
                disabled={loading || !selectedImage || !encryptPassword}
                className="w-full py-3 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-600 text-white font-medium rounded-lg transition-colors flex items-center justify-center"
              >
                {loading ? (
                  <div className="animate-spin w-5 h-5 border-2 border-white border-t-transparent rounded-full mr-2"></div>
                ) : (
                  <Lock className="w-5 h-5 mr-2" />
                )}
                {loading ? 'Encrypting...' : 'Encrypt & Download'}
              </button>
            </div>
          ) : (
            <div className="bg-white/10 backdrop-blur-sm rounded-2xl p-8 border border-white/20">
              <h2 className="text-2xl font-bold text-white mb-6 flex items-center">
                <Unlock className="w-6 h-6 mr-2 text-teal-400" />
                Decrypt Image
              </h2>
              
              {/* Text File Upload */}
              <div className="mb-6">
                <label className="block text-slate-300 mb-2">Select Encrypted Text File</label>
                <div className="relative">
                  <input
                    type="file"
                    accept=".txt"
                    onChange={handleTextFileUpload}
                    className="hidden"
                    id="text-upload"
                  />
                  <label
                    htmlFor="text-upload"
                    className="block w-full p-6 border-2 border-dashed border-slate-500 rounded-lg text-center cursor-pointer hover:border-teal-400 transition-colors bg-slate-800/50"
                  >
                    {selectedTextFile ? (
                      <div className="flex items-center justify-center">
                        <FileText className="w-8 h-8 mr-2 text-teal-300" />
                        <span className="text-teal-300">{selectedTextFile.name}</span>
                      </div>
                    ) : (
                      <div>
                        <Upload className="w-8 h-8 mx-auto mb-2 text-slate-400" />
                        <span className="text-slate-400">Click to select encrypted text file</span>
                      </div>
                    )}
                  </label>
                </div>
              </div>

              {/* Password Input */}
              <div className="mb-6">
                <label className="block text-slate-300 mb-2">Decryption Password</label>
                <div className="relative">
                  <input
                    type={showDecryptPassword ? 'text' : 'password'}
                    value={decryptPassword}
                    onChange={(e) => setDecryptPassword(e.target.value)}
                    placeholder="Enter your password"
                    className="w-full px-4 py-3 pr-12 bg-slate-800/50 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:border-teal-400 focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowDecryptPassword(!showDecryptPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-white"
                  >
                    {showDecryptPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              {/* Decrypt Button */}
              <button
                onClick={handleDecrypt}
                disabled={loading || !selectedTextFile || !decryptPassword}
                className="w-full py-3 bg-teal-500 hover:bg-teal-600 disabled:bg-gray-600 text-white font-medium rounded-lg transition-colors flex items-center justify-center mb-6"
              >
                {loading ? (
                  <div className="animate-spin w-5 h-5 border-2 border-white border-t-transparent rounded-full mr-2"></div>
                ) : (
                  <Unlock className="w-5 h-5 mr-2" />
                )}
                {loading ? 'Decrypting...' : 'Decrypt Image'}
              </button>

              {/* Decrypted Image Display */}
              {decryptedImage && (
                <div className="bg-slate-800/50 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-white font-medium">Decrypted Image:</h3>
                    <button
                      onClick={downloadDecryptedImage}
                      className="px-3 py-1 bg-teal-500 hover:bg-teal-600 text-white text-sm rounded-lg transition-colors flex items-center"
                    >
                      <Download className="w-4 h-4 mr-1" />
                      Download
                    </button>
                  </div>
                  <img
                    src={`data:image/jpeg;base64,${decryptedImage}`}
                    alt="Decrypted"
                    className="max-w-full h-auto rounded-lg border border-slate-600"
                  />
                </div>
              )}
            </div>
          )}
        </div>

        {/* Security Notice */}
        <div className="max-w-2xl mx-auto mt-8 bg-yellow-500/10 backdrop-blur-sm rounded-lg p-6 border border-yellow-500/30">
          <div className="flex items-start">
            <AlertTriangle className="w-6 h-6 text-yellow-400 mr-3 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-yellow-300 font-medium mb-2">Security Notice</h3>
              <ul className="text-yellow-200 text-sm space-y-1">
                <li>• All encryption happens locally in your browser - no data is sent to any server</li>
                <li>• After 3 failed decryption attempts, file access will be blocked for security</li>
                <li>• Use strong passwords and keep your encrypted files safe</li>
                <li>• This uses AES-CBC encryption with PBKDF2 key derivation (100,000 iterations)</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Technical Details */}
        <div className="max-w-2xl mx-auto mt-6 bg-blue-500/10 backdrop-blur-sm rounded-lg p-6 border border-blue-500/30">
          <div className="flex items-start">
            <Shield className="w-6 h-6 text-blue-400 mr-3 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-blue-300 font-medium mb-2">Encryption Details</h3>
              <ul className="text-blue-200 text-sm space-y-1">
                <li>• <strong>Algorithm:</strong> AES-256 in CBC mode</li>
                <li>• <strong>Key Derivation:</strong> PBKDF2 with SHA-256 (100,000 iterations)</li>
                <li>• <strong>Security:</strong> Random salt and IV for each encryption</li>
                <li>• <strong>Implementation:</strong> Java-style cryptography patterns in JavaScript</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;