// AI Provider
export interface AIProvider {
  analyzeText(text: string): Promise<any>;
  generateSummary(text: string): Promise<string>;
}

// Threat Intelligence Provider
export interface ThreatIntelligenceProvider {
  analyzeIP(ip: string): Promise<any>;
  analyzeDomain(domain: string): Promise<any>;
  analyzeHash(hash: string): Promise<any>;
}

// Geolocation Provider
export interface GeolocationProvider {
  lookup(ip: string): Promise<any>;
}

// Storage Provider
export interface StorageProvider {
  uploadFile(path: string, content: Buffer, contentType?: string): Promise<string>;
  downloadFile(path: string): Promise<Buffer>;
  deleteFile(path: string): Promise<void>;
  getSignedUrl(path: string): Promise<string>;
}

// Notification Provider
export interface NotificationProvider {
  sendEmail(to: string, subject: string, body: string): Promise<void>;
  sendSMS(to: string, message: string): Promise<void>;
  sendPush(token: string, payload: any): Promise<void>;
}

// Email Pipeline Provider
export interface EmailPipelineProvider {
  processIncomingEmail(rawEmail: string): Promise<any>;
}
