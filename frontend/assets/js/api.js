const API = {

    _base: 'http://127.0.0.1:5000',

    _getToken(endpoint) {

        if (endpoint.startsWith('/api/admin')) {
            return sessionStorage.getItem('Atoken') || null;
        }

        if (
            endpoint.startsWith('/api/user') ||
            endpoint.startsWith('/api/scan') ||
            endpoint.startsWith('/api/analytics')
        ) {
            return sessionStorage.getItem('Utoken') || null;
        }

        if (endpoint.startsWith('/api/auth')) {
            return null;
        }

        return null;
    },

    _headers(endpoint) {

        const token = this._getToken(endpoint);

        return {
            'Content-Type': 'application/json',

            ...(token
                ? {
                    'Authorization': 'Bearer ' + token
                }
                : {})
        };
    },

    get(endpoint) {

        return fetch(this._base + endpoint, {
            method: 'GET',
            headers: this._headers(endpoint)
        });
    },

    post(endpoint, body) {

        return fetch(this._base + endpoint, {
            method: 'POST',
            headers: this._headers(endpoint),
            body: JSON.stringify(body)
        });
    },

    patch(endpoint, body) {

        return fetch(this._base + endpoint, {
            method: 'PATCH',
            headers: this._headers(endpoint),
            body: JSON.stringify(body)
        });
    },

    del(endpoint) {

        return fetch(this._base + endpoint, {
            method: 'DELETE',
            headers: this._headers(endpoint)
        });
    }
};