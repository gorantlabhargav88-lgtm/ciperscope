const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000/api/v1';

class ApiClient {
  private organizationId: string | null = null;

  setOrganizationId(id: string | null) {
    this.organizationId = id;
  }

  getOrganizationId() {
    return this.organizationId;
  }

  async fetch(endpoint: string, options: RequestInit = {}) {
    const headers = new Headers(options.headers || {});
    
    headers.set('Content-Type', 'application/json');
    if (this.organizationId) {
      headers.set('x-organization-id', this.organizationId);
    }

    const config: RequestInit = {
      ...options,
      headers,
      credentials: 'include', // Important for cookies (auth)
    };

    const response = await fetch(`${BASE_URL}${endpoint}`, config);

    if (!response.ok) {
      // Handle 401 Unauthorized globally if needed
      if (response.status === 401) {
        // We could trigger a global logout event here
        window.dispatchEvent(new CustomEvent('auth:unauthorized'));
      }
      
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `API Error: ${response.status}`);
    }

    // For 204 No Content
    if (response.status === 204) {
      return null;
    }

    return response.json();
  }

  // Convenience methods
  async get(endpoint: string, options?: RequestInit) {
    return this.fetch(endpoint, { ...options, method: 'GET' });
  }

  async post(endpoint: string, data?: any, options?: RequestInit) {
    return this.fetch(endpoint, {
      ...options,
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async put(endpoint: string, data?: any, options?: RequestInit) {
    return this.fetch(endpoint, {
      ...options,
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async patch(endpoint: string, data?: any, options?: RequestInit) {
    return this.fetch(endpoint, {
      ...options,
      method: 'PATCH',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async delete(endpoint: string, options?: RequestInit) {
    return this.fetch(endpoint, { ...options, method: 'DELETE' });
  }
}

export const api = new ApiClient();
