import React, { useState, useEffect } from 'react';
import { Key, Download, Upload, Copy, Trash2, Plus, Save } from 'lucide-react';
import { generateSecurePassword, calculatePasswordStrength } from '../utils/crypto';
import { LogEntry, CryptoKey } from '../types';
import PasswordStrengthMeter from './PasswordStrengthMeter';

interface KeyManagementTabProps {
  onLog: (entry: Omit<LogEntry, 'id' | 'timestamp'>) => void;
}

export default function KeyManagementTab({ onLog }: KeyManagementTabProps) {
  const [keys, setKeys] = useState<CryptoKey[]>([]);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyPassword, setNewKeyPassword] = useState('');
  const [importData, setImportData] = useState('');

  // Load keys from localStorage on component mount
  useEffect(() => {
    const savedKeys = localStorage.getItem('cryptoKeys');
    if (savedKeys) {
      try {
        setKeys(JSON.parse(savedKeys));
      } catch (error) {
        console.error('Failed to load saved keys:', error);
      }
    }
  }, []);

  // Save keys to localStorage whenever keys change
  useEffect(() => {
    localStorage.setItem('cryptoKeys', JSON.stringify(keys));
  }, [keys]);

  const passwordStrength = calculatePasswordStrength(newKeyPassword);

  const generateNewKey = () => {
    if (!newKeyName.trim()) {
      onLog({
        action: 'error',
        algorithm: 'N/A',
        status: 'error',
        message: 'Key name is required'
      });
      return;
    }

    if (!newKeyPassword) {
      onLog({
        action: 'error',
        algorithm: 'N/A',
        status: 'error',
        message: 'Password is required for key generation'
      });
      return;
    }

    if (passwordStrength.score < 60) {
      onLog({
        action: 'key_generated',
        algorithm: 'AES-256-GCM',
        status: 'warning',
        message: 'Password strength is below recommended level'
      });
    }

    const newKey: CryptoKey = {
      id: Date.now().toString(),
      name: newKeyName.trim(),
      algorithm: 'AES-256-GCM',
      created: new Date().toISOString(),
      keyData: btoa(newKeyPassword) // Base64 encode for storage
    };

    setKeys(prev => [...prev, newKey]);
    setNewKeyName('');
    setNewKeyPassword('');

    onLog({
      action: 'key_generated',
      algorithm: 'AES-256-GCM',
      status: 'success',
      message: `Successfully generated key: ${newKey.name}`
    });
  };

  const generateRandomPassword = () => {
    const password = generateSecurePassword(32);
    setNewKeyPassword(password);
  };

  const exportKey = (key: CryptoKey) => {
    const keyData = {
      id: key.id,
      name: key.name,
      algorithm: key.algorithm,
      created: key.created,
      keyData: key.keyData
    };

    const blob = new Blob([JSON.stringify(keyData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${key.name}.cryptokey`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    onLog({
      action: 'key_exported',
      algorithm: key.algorithm,
      status: 'success',
      message: `Exported key: ${key.name}`
    });
  };

  const importKey = () => {
    if (!importData.trim()) {
      onLog({
        action: 'error',
        algorithm: 'N/A',
        status: 'error',
        message: 'No key data provided for import'
      });
      return;
    }

    try {
      const keyData = JSON.parse(importData);
      
      // Validate key structure
      if (!keyData.id || !keyData.name || !keyData.algorithm || !keyData.keyData) {
        throw new Error('Invalid key format');
      }

      // Check if key already exists
      if (keys.some(k => k.id === keyData.id)) {
        onLog({
          action: 'key_imported',
          algorithm: keyData.algorithm,
          status: 'warning',
          message: `Key ${keyData.name} already exists`
        });
        return;
      }

      const importedKey: CryptoKey = {
        id: keyData.id,
        name: keyData.name,
        algorithm: keyData.algorithm,
        created: keyData.created,
        keyData: keyData.keyData
      };

      setKeys(prev => [...prev, importedKey]);
      setImportData('');

      onLog({
        action: 'key_imported',
        algorithm: importedKey.algorithm,
        status: 'success',
        message: `Successfully imported key: ${importedKey.name}`
      });

    } catch (error) {
      onLog({
        action: 'key_imported',
        algorithm: 'N/A',
        status: 'error',
        message: `Failed to import key: ${error instanceof Error ? error.message : 'Invalid format'}`
      });
    }
  };

  const copyPassword = async (key: CryptoKey) => {
    try {
      const password = atob(key.keyData); // Decode from Base64
      await navigator.clipboard.writeText(password);
      
      onLog({
        action: 'key_exported',
        algorithm: key.algorithm,
        status: 'success',
        message: `Password copied to clipboard for key: ${key.name}`
      });
    } catch (error) {
      onLog({
        action: 'error',
        algorithm: key.algorithm,
        status: 'error',
        message: 'Failed to copy password to clipboard'
      });
    }
  };

  const deleteKey = (keyId: string) => {
    const keyToDelete = keys.find(k => k.id === keyId);
    if (keyToDelete) {
      setKeys(prev => prev.filter(k => k.id !== keyId));
      
      onLog({
        action: 'key_exported',
        algorithm: keyToDelete.algorithm,
        status: 'success',
        message: `Deleted key: ${keyToDelete.name}`
      });
    }
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
          Key Management
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Generate, import, export, and manage your encryption keys securely
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Generate New Key */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center space-x-2">
            <Plus className="w-5 h-5" />
            <span>Generate New Key</span>
          </h3>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Key Name
              </label>
              <input
                type="text"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="e.g., Personal Documents Key"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  type="password"
                  value={newKeyPassword}
                  onChange={(e) => setNewKeyPassword(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Enter a strong password..."
                />
                <button
                  onClick={generateRandomPassword}
                  className="absolute right-2 top-2 p-2 text-blue-500 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
                  title="Generate random password"
                >
                  <Key className="w-5 h-5" />
                </button>
              </div>
              {newKeyPassword && (
                <div className="mt-2">
                  <PasswordStrengthMeter strength={passwordStrength} />
                </div>
              )}
            </div>

            <button
              onClick={generateNewKey}
              disabled={!newKeyName.trim() || !newKeyPassword || passwordStrength.score < 40}
              className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 px-6 rounded-lg font-semibold hover:from-blue-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 flex items-center justify-center space-x-2"
            >
              <Save className="w-5 h-5" />
              <span>Generate Key</span>
            </button>
          </div>
        </div>

        {/* Import Key */}
        <div className="bg-gray-50 dark:bg-gray-700 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center space-x-2">
            <Upload className="w-5 h-5" />
            <span>Import Key</span>
          </h3>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Key Data (JSON)
              </label>
              <textarea
                value={importData}
                onChange={(e) => setImportData(e.target.value)}
                rows={8}
                className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-green-500 focus:border-green-500 font-mono text-sm"
                placeholder="Paste exported key data here..."
              />
            </div>

            <button
              onClick={importKey}
              disabled={!importData.trim()}
              className="w-full bg-gradient-to-r from-green-600 to-teal-600 text-white py-3 px-6 rounded-lg font-semibold hover:from-green-700 hover:to-teal-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 flex items-center justify-center space-x-2"
            >
              <Upload className="w-5 h-5" />
              <span>Import Key</span>
            </button>
          </div>
        </div>
      </div>

      {/* Stored Keys */}
      <div className="mt-8">
        <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-6">
          Stored Keys ({keys.length})
        </h3>

        {keys.length === 0 ? (
          <div className="text-center py-12 bg-gray-50 dark:bg-gray-700 rounded-xl">
            <Key className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-500 dark:text-gray-400">No keys stored yet</p>
            <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">
              Generate or import a key to get started
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            {keys.map((key) => (
              <div
                key={key.id}
                className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700"
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <div className="p-2 bg-gradient-to-br from-blue-600 to-purple-600 rounded-lg">
                      <Key className="w-5 h-5 text-white" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-gray-900 dark:text-white">
                        {key.name}
                      </h4>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {key.algorithm}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => deleteKey(key.id)}
                    className="text-red-500 hover:text-red-600 p-1 rounded hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                    title="Delete key"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>

                <div className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                  <p>Created: {new Date(key.created).toLocaleDateString()}</p>
                </div>

                <div className="flex space-x-2">
                  <button
                    onClick={() => exportKey(key)}
                    className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-3 py-2 rounded-lg text-sm font-medium transition-colors flex items-center justify-center space-x-1"
                    title="Export key"
                  >
                    <Download className="w-4 h-4" />
                    <span>Export</span>
                  </button>
                  <button
                    onClick={() => copyPassword(key)}
                    className="flex-1 bg-gray-600 hover:bg-gray-700 dark:bg-gray-700 dark:hover:bg-gray-600 text-white px-3 py-2 rounded-lg text-sm font-medium transition-colors flex items-center justify-center space-x-1"
                    title="Copy password"
                  >
                    <Copy className="w-4 h-4" />
                    <span>Copy</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}