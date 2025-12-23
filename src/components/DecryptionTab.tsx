import React, { useState, useCallback } from 'react';
import { Unlock, Eye, EyeOff, Download, AlertCircle, CheckCircle, Shield, Key } from 'lucide-react';
import { decryptFile, parseEncryptedBlob, verifyFileIntegrity } from '../utils/crypto';
import { LogEntry, EncryptionProgress } from '../types';
import FileDropZone from './FileDropZone';
import ProgressBar from './ProgressBar';

interface DecryptionTabProps {
  onLog: (entry: Omit<LogEntry, 'id' | 'timestamp'>) => void;
}

export default function DecryptionTab({ onLog }: DecryptionTabProps) {
  const [encryptedFiles, setEncryptedFiles] = useState<File[]>([]);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptionProgress, setDecryptionProgress] = useState<EncryptionProgress[]>([]);
  const [decryptedFiles, setDecryptedFiles] = useState<Array<{ data: ArrayBuffer; filename: string; originalFile: File }>>([]);
  const [verificationResults, setVerificationResults] = useState<Record<string, boolean>>({});

  const handleFilesDrop = useCallback((droppedFiles: File[]) => {
    // Filter only encrypted files (basic check by extension or name)
    const filteredFiles = droppedFiles.filter(file =>
      file.name.includes('.encrypted') || file.name.endsWith('.enc') || file.type === 'application/octet-stream'
    );
    setEncryptedFiles(prev => [...prev, ...filteredFiles]);
  }, []);

  const removeFile = (index: number) => {
    setEncryptedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const decryptFiles = async () => {
    if (encryptedFiles.length === 0) {
      onLog({
        action: 'error',
        algorithm: 'N/A',
        status: 'error',
        message: 'No encrypted files selected for decryption'
      });
      return;
    }
    if (!password) {
      onLog({
        action: 'error',
        algorithm: 'N/A',
        status: 'error',
        message: 'Password is required for decryption'
      });
      return;
    }
    setIsDecrypting(true);
    setDecryptionProgress(encryptedFiles.map(file => ({
      filename: file.name,
      progress: 0,
      status: 'pending'
    })));
    const newDecryptedFiles: Array<{ data: ArrayBuffer; filename: string; originalFile: File }> = [];
    const newVerificationResults: Record<string, boolean> = {};
    try {
      for (let i = 0; i < encryptedFiles.length; i++) {
        const file = encryptedFiles[i];
       
        setDecryptionProgress(prev => prev.map((item, index) =>
          index === i ? { ...item, status: 'processing', progress: 0 } : item
        ));
        try {
          // Parse the encrypted file
          const encryptedFileData = await parseEncryptedBlob(file);
         
          // Verify integrity first
          const isValid = await verifyFileIntegrity(encryptedFileData, password);
          newVerificationResults[file.name] = isValid;
          if (!isValid) {
            throw new Error('Invalid password or corrupted file');
          }
          // Decrypt the file
          const decryptedResult = await decryptFile(encryptedFileData, password, (progress) => {
            setDecryptionProgress(prev => prev.map((item, index) =>
              index === i ? { ...item, progress } : item
            ));
          });
          newDecryptedFiles.push({
            data: decryptedResult.data,
            filename: decryptedResult.filename,
            originalFile: file
          });
          setDecryptionProgress(prev => prev.map((item, index) =>
            index === i ? { ...item, status: 'completed', progress: 100 } : item
          ));
          onLog({
            action: 'decrypt',
            filename: file.name,
            algorithm: encryptedFileData.algorithm,
            status: 'success',
            message: `Successfully decrypted ${file.name}`
          });
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
         
          setDecryptionProgress(prev => prev.map((item, index) =>
            index === i ? { ...item, status: 'error', error: errorMessage } : item
          ));
          onLog({
            action: 'decrypt',
            filename: file.name,
            algorithm: 'AES-256-GCM',
            status: 'error',
            message: `Failed to decrypt ${file.name}: ${errorMessage}`
          });
        }
      }
    } finally {
      setIsDecrypting(false);
      setDecryptedFiles(newDecryptedFiles);
      setVerificationResults(newVerificationResults);
      // Clear progress if all done
      if (newDecryptedFiles.length === encryptedFiles.length) {
        setDecryptionProgress([]);
      }
    }
  };

  const downloadDecryptedFile = (item: { data: ArrayBuffer; filename: string }) => {
    const blob = new Blob([item.data]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = item.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadAllDecrypted = () => {
    decryptedFiles.forEach(item => downloadDecryptedFile(item));
  };

  const clearAll = () => {
    setEncryptedFiles([]);
    setDecryptionProgress([]);
    setDecryptedFiles([]);
    setVerificationResults({});
    setPassword('');
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
          File Decryption
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Decrypt your encrypted files with the correct password
        </p>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* File Selection */}
        <div className="space-y-6">
          <div>
            <FileDropZone
              onFilesDrop={handleFilesDrop}
              acceptedTypes=".encrypted,.enc"
              description="Drop encrypted files here or click to browse"
            />
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              Accepted formats: .encrypted, .enc files
            </p>
          </div>
          {encryptedFiles.length > 0 && (
            <div className="bg-gray-50 dark:bg-gray-700 rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Encrypted Files ({encryptedFiles.length})
                </h3>
                <button
                  onClick={clearAll}
                  className="text-red-500 hover:text-red-600 p-2 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors text-sm"
                >
                  Clear All
                </button>
              </div>
             
              <div className="space-y-3 max-h-64 overflow-y-auto">
                {encryptedFiles.map((file, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-lg shadow-sm"
                  >
                    <div className="flex items-center space-x-3">
                      <Shield className="w-5 h-5 text-purple-500" />
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white truncate max-w-xs">
                          {file.name}
                        </p>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          {(file.size / 1024 / 1024).toFixed(2)} MB
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => removeFile(index)}
                      className="text-gray-400 hover:text-red-500 p-1 rounded transition-colors text-sm"
                      title="Remove file"
                    >
                      Remove
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        {/* Decryption Settings */}
        <div className="space-y-6">
          <div className="bg-gray-50 dark:bg-gray-700 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Decryption Settings
            </h3>
           
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Decryption Password
                </label>
                <div className="relative">
                  <div className="relative flex items-center">
                    <Key className="absolute left-3 w-5 h-5 text-gray-400 pointer-events-none" />
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full pl-12 pr-12 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:border-purple-500 transition-all duration-200 ease-in-out shadow-sm hover:shadow-md"
                      placeholder="Enter the password used for encryption..."
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors duration-200"
                      title={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                </div>
              </div>
              <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4">
                <div className="flex items-start space-x-3">
                  <Unlock className="w-5 h-5 text-purple-500 mt-0.5" />
                  <div className="text-sm text-purple-700 dark:text-purple-300">
                    <p className="font-medium mb-1">Secure Decryption</p>
                    <p>Files will be verified for integrity before decryption. The original file structure and metadata will be restored.</p>
                  </div>
                </div>
              </div>
              <button
                onClick={decryptFiles}
                disabled={encryptedFiles.length === 0 || !password || isDecrypting}
                className="w-full bg-gradient-to-r from-purple-600 to-pink-600 text-white py-3 px-6 rounded-lg font-semibold hover:from-purple-700 hover:to-pink-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 flex items-center justify-center space-x-2"
              >
                <Unlock className="w-5 h-5" />
                <span>{isDecrypting ? 'Decrypting...' : 'Decrypt Files'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
      {/* Decryption Progress */}
      {decryptionProgress.length > 0 && (
        <div className="mt-8 bg-gray-50 dark:bg-gray-700 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Decryption Progress
          </h3>
          <div className="space-y-4">
            {decryptionProgress.map((item, index) => (
              <div key={index} className="bg-white dark:bg-gray-800 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-gray-900 dark:text-white truncate max-w-xs">
                    {item.filename}
                  </span>
                  <div className="flex items-center space-x-2">
                    {item.status === 'completed' && (
                      <CheckCircle className="w-5 h-5 text-green-500" />
                    )}
                    {item.status === 'error' && (
                      <AlertCircle className="w-5 h-5 text-red-500" />
                    )}
                    <span className="text-sm text-gray-500 dark:text-gray-400">
                      {item.progress}%
                    </span>
                  </div>
                </div>
                <ProgressBar progress={item.progress} status={item.status} />
                {item.error && (
                  <p className="mt-2 text-sm text-red-500">{item.error}</p>
                )}
                {item.status === 'completed' && verificationResults[item.filename] && (
                  <div className="mt-2 flex items-center space-x-2 text-sm text-green-600 dark:text-green-400">
                    <CheckCircle className="w-4 h-4" />
                    <span>File integrity verified</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {/* Download Section */}
      {decryptedFiles.length > 0 && (
        <div className="mt-8 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-green-800 dark:text-green-200">
              Decryption Complete! ({decryptedFiles.length}/{encryptedFiles.length} files)
            </h3>
            <button
              onClick={downloadAllDecrypted}
              className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg font-medium transition-colors flex items-center space-x-2"
            >
              <Download className="w-4 h-4" />
              <span>Download All</span>
            </button>
          </div>
         
          <div className="space-y-2">
            {decryptedFiles.map((item, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-lg"
              >
                <div className="flex items-center space-x-3">
                  <CheckCircle className="w-5 h-5 text-green-500" />
                  <span className="font-medium text-gray-900 dark:text-white">
                    {item.filename}
                  </span>
                </div>
                <button
                  onClick={() => downloadDecryptedFile(item)}
                  className="text-green-600 hover:text-green-700 dark:text-green-400 dark:hover:text-green-300 p-2 rounded-lg hover:bg-green-100 dark:hover:bg-green-900/20 transition-colors"
                  title="Download decrypted file"
                >
                  <Download className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
