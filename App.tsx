import React, { useState } from 'react';
import {
  Shield,
  Lock,
  Unlock,
  Upload,
  Download,
  AlertTriangle,
  Eye,
  EyeOff,
  FileText,
  Image as ImageIcon
} from 'lucide-react';
import { AESUtil } from './utils/AESUtil';
import { SecurityManager } from './utils/SecurityManager';

/**
 *  Snap Crypt – Nvidia Green Edition
 *  -----------------------------------
 *  All styling refactored for a neon-green ("Nvidia") color palette.
 *  Business logic unchanged.
 */

function App() {
  const [mode, setMode] = useState<'encrypt' | 'decrypt'>('encrypt');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState<'success' | 'error' | 'warning'>('success');

  // Encrypt
  const [selectedImage, setSelectedImage] = useState<File | null>(null);
  const [encryptPassword, setEncryptPassword] = useState('');
  const [showEncryptPassword, setShowEncryptPassword] = useState(false);

  // Decrypt
  const [selectedTextFile, setSelectedTextFile] = useState<File | null>(null);
  const [decryptPassword, setDecryptPassword] = useState('');
  const [showDecryptPassword, setShowDecryptPassword] = useState(false);
  const [decryptedImage, setDecryptedImage] = useState<string | null>(null);

  const showMessage = (msg: string, type: 'success' | 'error' | 'warning' = 'success') => {
    setMessage(msg);
    setMessageType(type);
    setTimeout(() => setMessage(''), 5_000);
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && file.type.startsWith('image/')) setSelectedImage(file);
    else showMessage('Please select a valid image file', 'error');
  };

  const handleTextFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && file.type === 'text/plain') setSelectedTextFile(file);
    else showMessage('Please select a valid .txt file', 'error');
  };

  const handleEncrypt = async () => {
    if (!selectedImage || !encryptPassword) {
      showMessage('Select an image and enter a password', 'error');
      return;
    }
    if (encryptPassword.length < 8) {
      showMessage('Password must be at least 8 characters', 'error');
      return;
    }

    setLoading(true);
    try {
      const imageBase64 = await AESUtil.fileToBase64(selectedImage);
      const encryptedData = AESUtil.encrypt(imageBase64, encryptPassword);

      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `encrypted_${selectedImage.name.split('.')[0]}_${ts}.txt`;

      AESUtil.downloadEncryptedFile(encryptedData, filename);

      showMessage('Image encrypted 🎉 Download starting…', 'success');
      setSelectedImage(null);
      setEncryptPassword('');
      (document.getElementById('image-upload') as HTMLInputElement).value = '';
    } catch (err) {
      showMessage('Encryption failed: ' + (err as Error).message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!selectedTextFile || !decryptPassword) {
      showMessage('Select an encrypted file and enter the password', 'error');
      return;
    }

    setLoading(true);
    try {
      const fileContent = await new Promise<string>((res, rej) => {
        const r = new FileReader();
        r.onload = () => res(r.result as string);
        r.onerror = () => rej(new Error('Failed to read file'));
        r.readAsText(selectedTextFile);
      });

      const fileHash = SecurityManager.createFileHash(fileContent);
      if (SecurityManager.isFileBlocked(fileHash)) {
        showMessage('File access denied – too many failed attempts', 'error');
        setSelectedTextFile(null);
        (document.getElementById('text-upload') as HTMLInputElement).value = '';
        return;
      }

      try {
        const decryptedBase64 = AESUtil.decrypt(fileContent, decryptPassword);
        SecurityManager.clearFailedAttempts(fileHash);

        setDecryptedImage(decryptedBase64);
        showMessage('Image decrypted ✓', 'success');
        setDecryptPassword('');
      } catch {
        const remaining = SecurityManager.recordFailedAttempt(fileHash);
        if (remaining === 0) {
          showMessage('Maximum attempts exceeded – file blocked', 'error');
          setSelectedTextFile(null);
          (document.getElementById('text-upload') as HTMLInputElement).value = '';
        } else {
          showMessage(`Incorrect password – ${remaining} attempts left`, 'warning');
        }
      }
    } catch (err) {
      showMessage('Failed to read encrypted file: ' + (err as Error).message, 'error');
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
    (document.getElementById('image-upload') as HTMLInputElement).value = '';
    (document.getElementById('text-upload') as HTMLInputElement).value = '';
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
    // <div className="min-h-screen w-full bg-gradient-to-br from-[#1f3322] via-[#203b1d] to-[#0d2416] text-white font-inter selection:bg-lime-400/40">
    //#FFCCF2, #977DFF, #0033FF
    <div
  className="min-h-screen"
  style={{
    backgroundImage: `linear-gradient(to bottom right, #7F55B1, #5459AC, #648DB3)`,
    transition: 'background-image 0.7s ease-in-out',
  }}
>


      <div className="max-w-6xl mx-auto px-4 py-10">
        {/* Header */}
        <header className="text-center mb-10">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-12 h-12 text-lime-400 drop-shadow-[0_3px_30px_rgba(163,255,69,0.8)]" />
            <h1 className="text-5xl font-black tracking-tight whitespace-nowrap">
              Snap<span className="text-lime-400">Crypt</span>
            </h1>
          </div>
          <p className="text-lg text-lime-300/90 mb-1">
            Client-Side Image Encryption with AES-CBC &amp; PBKDF2
          </p>
          <p className="text-lime-100/80 text-sm">
            All encryption happens in your browser - no data leaves your device
          </p>
        </header>

        {/* Mode Switch */}
        <div className="flex justify-center mb-12">
          <div className="bg-white/10 backdrop-blur-md rounded-full p-1 flex shadow-inner-glass">
            {(['encrypt', 'decrypt'] as const).map((m) => (
              <button
                key={m}
                onClick={() => {
                  setMode(m);
                  resetForm();
                }}
                className={`relative flex items-center gap-2 px-8 py-3 rounded-full font-semibold transition
                  ${mode === m
                    ? 'bg-gradient-to-r from-lime-400 to-green-500 text-zinc-900 shadow-lg shadow-lime-400/40'
                    : 'hover:bg-lime-400/10 text-lime-200'
                  }
                `}
              >
                {m === 'encrypt' ? <Lock className="w-4 h-4" /> : <Unlock className="w-4 h-4" />}
                {m === 'encrypt' ? 'Encrypt' : 'Decrypt'}
              </button>
            ))}
          </div>
        </div>

        {/* Alerts */}
        {message && (
          <div
            className={`mx-auto max-w-2xl mb-10 px-5 py-4 rounded-xl flex items-center gap-3 ring-1
              ${
                messageType === 'success'
                  ? 'bg-lime-500/15 ring-lime-500 text-lime-200'
                  : messageType === 'warning'
                  ? 'bg-yellow-500/20 ring-yellow-400 text-yellow-200'
                  : 'bg-red-600/10 ring-red-600 text-red-200'
              }
            `}
          >
            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
            <span className="text-sm font-medium">{message}</span>
          </div>
        )}

        {/* Card */}
        <main className="mx-auto max-w-3xl bg-white/10 backdrop-blur-md rounded-3xl p-10 ring-1 ring-lime-400/20 shadow-[0_6px_28px_-8px_rgba(163,255,69,0.13)]">
          {mode === 'encrypt' ? (
            // Encrypt form
            <>
              <h2 className="text-3xl font-bold mb-8 flex items-center gap-2">
                <Lock className="w-6 h-6 text-lime-400" />
                Encrypt Image
              </h2>

              {/* Upload */}
              <div className="mb-8">
                <label className="block mb-2 text-lime-200">Choose an image</label>
                <div className="relative">
                  <input
                    id="image-upload"
                    type="file"
                    accept="image/*"
                    onChange={handleImageUpload}
                    className="hidden"
                  />
                  <label
                    htmlFor="image-upload"
                    className={`flex flex-col items-center justify-center gap-2 w-full p-8 rounded-xl border-2 border-dashed transition
                      ${
                        selectedImage
                          ? 'border-lime-400/80 bg-lime-400/10 text-lime-200'
                          : 'border-lime-400/20 hover:border-lime-400/70 text-white/80 hover:text-lime-200'
                      }`}
                  >
                    {selectedImage ? (
                      <>
                        <ImageIcon className="w-8 h-8" />
                        <span>{selectedImage.name}</span>
                      </>
                    ) : (
                      <>
                        <Upload className="w-8 h-8" />
                        <span className="text-sm">Click to select image</span>
                      </>
                    )}
                  </label>
                </div>
              </div>

              {/* Password */}
              <div className="mb-10">
                <label className="block mb-2 text-lime-200">Password</label>
                <div className="relative">
                  <input
                    type={showEncryptPassword ? 'text' : 'password'}
                    value={encryptPassword}
                    onChange={(e) => setEncryptPassword(e.target.value)}
                    placeholder="Min 8 characters"
                    className="w-full px-4 py-3 pr-12 rounded-lg bg-white/10 ring-1 ring-inset ring-lime-400/20 placeholder:text-lime-200 focus:outline-none focus:ring-2 focus:ring-lime-400"
                  />
                  <button
                    type="button"
                    onClick={() => setShowEncryptPassword(!showEncryptPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-lime-200 hover:text-lime-400"
                  >
                    {showEncryptPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
                <p className="text-lime-100/60 text-xs mt-1">
                  Use a strong password with mixed case, numbers, and symbols
                </p>
              </div>

              {/* Encrypt Button */}
              <button
                onClick={handleEncrypt}
                disabled={loading || !selectedImage || !encryptPassword}
                className="w-full relative overflow-hidden rounded-full bg-gradient-to-r from-lime-400 to-green-500 py-3 font-bold shadow-lg shadow-lime-400/40 disabled:opacity-50 disabled:cursor-not-allowed group transition"
              >
                <span className="absolute inset-0 bg-white/15 opacity-0 group-hover:opacity-60 transition rounded-full animate-ripple" />
                <div className="relative z-10 flex items-center justify-center gap-2">
                  {loading ? (
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <Lock className="w-5 h-5" />
                  )}
                  {loading ? 'Encrypting…' : 'Encrypt & Download'}
                </div>
              </button>
            </>
          ) : (
            // Decrypt form
            <>
              <h2 className="text-3xl font-bold mb-8 flex items-center gap-2">
                <Unlock className="w-6 h-6 text-lime-200" />
                Decrypt Image
              </h2>

              {/* Upload */}
              <div className="mb-8">
                <label className="block mb-2 text-lime-200">Choose encrypted .txt</label>
                <div className="relative">
                  <input
                    id="text-upload"
                    type="file"
                    accept=".txt"
                    onChange={handleTextFileUpload}
                    className="hidden"
                  />
                  <label
                    htmlFor="text-upload"
                    className={`flex flex-col items-center justify-center gap-2 w-full p-8 rounded-xl border-2 border-dashed transition
                      ${
                        selectedTextFile
                          ? 'border-lime-400/80 bg-lime-400/10 text-lime-200'
                          : 'border-lime-400/20 hover:border-lime-400/70 text-white/80 hover:text-lime-200'
                      }`}
                  >
                    {selectedTextFile ? (
                      <>
                        <FileText className="w-8 h-8" />
                        <span>{selectedTextFile.name}</span>
                      </>
                    ) : (
                      <>
                        <Upload className="w-8 h-8" />
                        <span className="text-sm">Click to select encrypted file</span>
                      </>
                    )}
                  </label>
                </div>
              </div>

              {/* Password */}
              <div className="mb-10">
                <label className="block mb-2 text-lime-200">Password</label>
                <div className="relative">
                  <input
                    type={showDecryptPassword ? 'text' : 'password'}
                    value={decryptPassword}
                    onChange={(e) => setDecryptPassword(e.target.value)}
                    placeholder="Enter password"
                    className="w-full px-4 py-3 pr-12 rounded-lg bg-white/10 ring-1 ring-inset ring-lime-400/20 placeholder:text-lime-200 focus:outline-none focus:ring-2 focus:ring-lime-400"
                  />
                  <button
                    type="button"
                    onClick={() => setShowDecryptPassword(!showDecryptPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-lime-200 hover:text-lime-400"
                  >
                    {showDecryptPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              {/* Decrypt Button */}
              <button
                onClick={handleDecrypt}
                disabled={loading || !selectedTextFile || !decryptPassword}
                className="w-full relative overflow-hidden rounded-full bg-gradient-to-r from-lime-400 to-green-500 py-3 font-bold shadow-lg shadow-lime-400/40 disabled:opacity-50 disabled:cursor-not-allowed group transition"
              >
                <span className="absolute inset-0 bg-white/15 opacity-0 group-hover:opacity-60 transition rounded-full animate-ripple" />
                <div className="relative z-10 flex items-center justify-center gap-2">
                  {loading ? (
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <Unlock className="w-5 h-5" />
                  )}
                  {loading ? 'Decrypting…' : 'Decrypt Image'}
                </div>
              </button>

              {/* Decrypted Preview */}
              {decryptedImage && (
                <div className="mt-10 bg-white/10 p-6 rounded-xl ring-1 ring-lime-200/20">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold text-lime-200">Decrypted Preview</h3>
                    <button
                      onClick={downloadDecryptedImage}
                      className="flex items-center gap-1 px-3 py-1.5 rounded-full bg-lime-400 hover:bg-lime-500 text-zinc-900 text-sm font-semibold shadow-md shadow-lime-600/50 transition"
                    >
                      <Download className="w-4 h-4" /> Download
                    </button>
                  </div>
                  <img
                    src={`data:image/jpeg;base64,${decryptedImage}`}
                    alt="Decrypted"
                    className="w-full max-h-[60vh] object-contain rounded-lg"
                  />
                </div>
              )}
            </>
          )}
        </main>

        {/* Footer Notice & Tech */}
        <section className="grid md:grid-cols-2 gap-6 mt-14">
          {/* Security */}
          <div className="bg-yellow-500/10 backdrop-blur-md p-6 rounded-2xl ring-1 ring-yellow-400/30">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-6 h-6 text-yellow-300 flex-shrink-0 mt-1" />
              <ul className="space-y-1 text-sm text-yellow-200/90">
                <li>• All encryption happens locally – files never leave your device.</li>
                <li>• Three failed password attempts lock the file (per-device).</li>
                <li>• Use strong, unique passwords and keep encrypted files safe.</li>
              </ul>
            </div>
          </div>

          {/* Tech */}
          <div className="bg-lime-500/10 backdrop-blur-md p-6 rounded-2xl ring-1 ring-lime-300/30">
            <div className="flex items-start gap-3">
              <Shield className="w-6 h-6 text-lime-400 flex-shrink-0 mt-1" />
              <ul className="space-y-1 text-sm text-lime-200/90">
                <li>• AES-256 in CBC mode with random IV &amp; salt.</li>
                <li>• PBKDF2-SHA-256 with 100,000 iterations for key derivation.</li>
                <li>• Built entirely with React + TypeScript, Tailwind CSS, Lucide icons.</li>
              </ul>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

export default App;
