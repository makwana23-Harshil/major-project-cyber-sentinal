/* =============================================
   CyberSentinel Pro — API Fetch Wrapper
============================================= */
const API = {
  _base: 'http://127.0.0.1:5000',

  _headers() {
    const token = getToken();
    return {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': 'Bearer ' + token } : {})
    };
  },

  get(endpoint) {
    return fetch(this._base + endpoint, { headers: this._headers() });
  },

  post(endpoint, body) {
    return fetch(this._base + endpoint, {
      method: 'POST',
      headers: this._headers(),
      body: JSON.stringify(body)
    });
  },

  del(endpoint) {
    return fetch(this._base + endpoint, {
      method: 'DELETE',
      headers: this._headers()
    });
  },

  patch(endpoint, body) {
    return fetch(this._base + endpoint, {
      method: 'PATCH',
      headers: this._headers(),
      body: JSON.stringify(body)
    });
  }
};
