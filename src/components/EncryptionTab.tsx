import React, { useState, useCallback } from 'react';
import { Upload, Lock, Download, Trash2, Plus, AlertCircle, CheckCircle } from 'lucide-react';
import { encryptFile, generateSecurePassword, calculatePasswordStrength, createDownloadBlob } from '../utils/crypto';
import { LogEntry, EncryptionProgress } from '../types';
import FileDropZone from './FileDropZone';
import PasswordStrengthMeter from './PasswordStrengthMeter';
import ProgressBar from './ProgressBar';

interface EncryptionTabProps {
  onLog: (entry: Omit<LogEntry, 'id' | 'timestamp'>) => void;
}

export default function EncryptionTab({ onLog }: EncryptionTabProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [password, setPassword] = useState('');
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [encryptionProgress, setEncryptionProgress] = useState<EncryptionProgress[]>([]);
  const [completedFiles, setCompletedFiles] = useState<Array<{ file: File; blob: Blob; filename: string }>>([]);
  
  const passwordStrength = calculatePasswordStrength(password);

  const handleFilesDrop = useCallback((droppedFiles: File[]) => {
    setFiles(prev => [...prev, ...droppedFiles]);
  }, []);

  const removeFile = (index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const generateRandomPassword = () => {
    const newPassword = generateSecurePassword();
    setPassword(newPassword);
  };

  const encryptFiles = async () => {
    if (files.length === 0) {
      onLog({
        action: 'error',
        algorithm: 'N/A',
        status: 'error',
        message: 'No files selected for encryption'
      });
      return;
    }
    if (!password) {
      onLog({
        action: 'error',
        algorithm: 'N/A',
        status: 'error',
        message: 'Password is required for encryption'
      });
      return;
    }
    if (passwordStrength.score < 40) {
      onLog({
        action: 'error',
        algorithm: 'AES-256-GCM',
        status: 'warning',
        message: 'Password strength is too weak for secure encryption'
      });
      return;
    }
    setIsEncrypting(true);
    setEncryptionProgress(files.map(file => ({
      filename: file.name,
      progress: 0,
      status: 'pending'
    })));
    const newCompletedFiles: Array<{ file: File; blob: Blob; filename: string }> = [];
    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setEncryptionProgress(prev => prev.map((item, index) =>
          index === i ? { ...item, status: 'processing', progress: 0 } : item
        ));
        try {
          const encryptedFile = await encryptFile(file, password, (progress) => {
            setEncryptionProgress(prev => prev.map((item, index) =>
              index === i ? { ...item, progress } : item
            ));
          });
          const blob = createDownloadBlob(encryptedFile);
          newCompletedFiles.push({
            file,
            blob,
            filename: encryptedFile.name
          });
          setEncryptionProgress(prev => prev.map((item, index) =>
            index === i ? { ...item, status: 'completed', progress: 100 } : item
          ));
          onLog({
            action: 'encrypt',
            filename: file.name,
            algorithm: 'AES-256-GCM',
            status: 'success',
            message: `Successfully encrypted ${file.name}`
          });
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          setEncryptionProgress(prev => prev.map((item, index) =>
            index === i ? { ...item, status: 'error', error: errorMessage } : item
          ));
          onLog({
            action: 'encrypt',
            filename: file.name,
            algorithm: 'AES-256-GCM',
            status: 'error',
            message: `Failed to encrypt ${file.name}: ${errorMessage}`
          });
        }
      }
    } finally {
      setIsEncrypting(false);
      setCompletedFiles(newCompletedFiles);
      // Clear progress if all done
      if (newCompletedFiles.length === files.length) {
        setEncryptionProgress([]);
      }
    }
  };

  const downloadFile = (item: { blob: Blob; filename: string }) => {
    const url = URL.createObjectURL(item.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = item.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadAllFiles = () => {
    completedFiles.forEach(item => downloadFile(item));
  };

  const clearAll = () => {
    setFiles([]);
    setEncryptionProgress([]);
    setCompletedFiles([]);
    setPassword('');
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
          File Encryption
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Encrypt your files using military-grade AES-256-GCM encryption
        </p>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* File Selection */}
        <div className="space-y-6">
          <FileDropZone onFilesDrop={handleFilesDrop} />
          {files.length > 0 && (
            <div className="bg-gray-50 dark:bg-gray-700 rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Selected Files ({files.length})
                </h3>
                <button
                  onClick={clearAll}
                  className="text-red-500 hover:text-red-600 p-2 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                  title="Clear all files"
                >
                  <Trash2 className="w-5 h-5" />
                </button>
              </div>
              <div className="space-y-3 max-h-64 overflow-y-auto">
                {files.map((file, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-lg shadow-sm"
                  >
                    <div className="flex items-center space-x-3">
                      <Upload className="w-5 h-5 text-blue-500" />
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
                      className="text-gray-400 hover:text-red-500 p-1 rounded transition-colors"
                      title="Remove file"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        {/* Encryption Settings */}
        <div className="space-y-6">
          <div className="bg-gray-50 dark:bg-gray-700 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Encryption Settings
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Encryption Password
                </label>
                <div className="relative">
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Enter a strong password..."
                  />
                  <button
                    onClick={generateRandomPassword}
                    className="absolute right-2 top-2 p-2 text-blue-500 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
                    title="Generate secure password"
                  >
                    <Plus className="w-5 h-5" />
                  </button>
                </div>
                {password && (
                  <div className="mt-2">
                    <PasswordStrengthMeter strength={passwordStrength} />
                  </div>
                )}
              </div>
              <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                <div className="flex items-start space-x-3">
                  <Lock className="w-5 h-5 text-blue-500 mt-0.5" />
                  <div className="text-sm text-blue-700 dark:text-blue-300">
                    <p className="font-medium mb-1">Algorithm: AES-256-GCM</p>
                    <p>Military-grade encryption with authenticated encryption and key derivation using PBKDF2 (100,000 iterations)</p>
                  </div>
                </div>
              </div>
              <button
                onClick={encryptFiles}
                disabled={files.length === 0 || !password || isEncrypting || passwordStrength.score < 40}
                className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 px-6 rounded-lg font-semibold hover:from-blue-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 flex items-center justify-center space-x-2"
              >
                <Lock className="w-5 h-5" />
                <span>{isEncrypting ? 'Encrypting...' : 'Encrypt Files'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
      {/* Encryption Progress */}
      {encryptionProgress.length > 0 && (
        <div className="mt-8 bg-gray-50 dark:bg-gray-700 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Encryption Progress
          </h3>
          <div className="space-y-4">
            {encryptionProgress.map((item, index) => (
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
              </div>
            ))}
          </div>
        </div>
      )}
      {/* Download Section */}
      {completedFiles.length > 0 && (
        <div className="mt-8 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-green-800 dark:text-green-200">
              Encryption Complete! ({completedFiles.length}/{files.length} files)
            </h3>
            <button
              onClick={downloadAllFiles}
              className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg font-medium transition-colors flex items-center space-x-2"
            >
              <Download className="w-4 h-4" />
              <span>Download All</span>
            </button>
          </div>
          <div className="space-y-2">
            {completedFiles.map((item, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-lg"
              >
                <span className="font-medium text-gray-900 dark:text-white truncate max-w-xs">
                  {item.filename}
                </span>
                <button
                  onClick={() => downloadFile(item)}
                  className="text-green-600 hover:text-green-700 dark:text-green-400 dark:hover:text-green-300 p-2 rounded-lg hover:bg-green-100 dark:hover:bg-green-900/20 transition-colors"
                  title="Download encrypted file"
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
