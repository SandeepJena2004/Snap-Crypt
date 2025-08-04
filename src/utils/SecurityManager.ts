/**
 * Security Manager for handling failed decryption attempts
 * Implements the 3-strike rule for file deletion
 */
export class SecurityManager {
  private static readonly MAX_ATTEMPTS = 3;
  private static readonly STORAGE_KEY = 'encryption_failed_attempts';

  /**
   * Records a failed decryption attempt for a file
   * @param fileHash - Hash of the file content to track attempts
   * @returns Remaining attempts before file deletion
   */
  static recordFailedAttempt(fileHash: string): number {
    const attempts = this.getFailedAttempts();
    const currentAttempts = (attempts[fileHash] || 0) + 1;
    
    if (currentAttempts >= this.MAX_ATTEMPTS) {
      // Remove from tracking as file should be deleted
      delete attempts[fileHash];
      this.saveFailedAttempts(attempts);
      return 0;
    } else {
      attempts[fileHash] = currentAttempts;
      this.saveFailedAttempts(attempts);
      return this.MAX_ATTEMPTS - currentAttempts;
    }
  }

  /**
   * Clears failed attempts for a file (on successful decryption)
   * @param fileHash - Hash of the file content
   */
  static clearFailedAttempts(fileHash: string): void {
    const attempts = this.getFailedAttempts();
    delete attempts[fileHash];
    this.saveFailedAttempts(attempts);
  }

  /**
   * Checks if a file has exceeded maximum attempts
   * @param fileHash - Hash of the file content
   * @returns True if file should be blocked
   */
  static isFileBlocked(fileHash: string): boolean {
    const attempts = this.getFailedAttempts();
    return (attempts[fileHash] || 0) >= this.MAX_ATTEMPTS;
  }

  /**
   * Gets the number of failed attempts for a file
   * @param fileHash - Hash of the file content
   * @returns Number of failed attempts
   */
  static getAttemptCount(fileHash: string): number {
    const attempts = this.getFailedAttempts();
    return attempts[fileHash] || 0;
  }

  /**
   * Creates a simple hash of file content for tracking
   * @param content - File content as string
   * @returns Simple hash string
   */
  static createFileHash(content: string): string {
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
  }

  private static getFailedAttempts(): Record<string, number> {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY);
      return stored ? JSON.parse(stored) : {};
    } catch {
      return {};
    }
  }

  private static saveFailedAttempts(attempts: Record<string, number>): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(attempts));
    } catch {
      // Handle storage errors silently
    }
  }
}