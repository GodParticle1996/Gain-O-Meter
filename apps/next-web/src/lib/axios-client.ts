import axios from 'axios'

const options = {
  baseURL: process.env.NEXT_PUBLIC_API_BASE_URL,
  // NOTE: withCredentials will send cookies to the server
  withCredentials: true,
  timeout: 10000,
}

const API = axios.create(options)

export const APIRefresh = axios.create(options)
APIRefresh.interceptors.response.use((response) => response)

API.interceptors.response.use(
  // Handle successful responses
  (response) => {
    return response
  },
  // Handle errors in responses
  async (error) => {
    // Destructure the error response to get data and status
    const { data, status } = error.response

    // Check if error is due to missing auth token and status is unauthorized (401)
    if (data.errorCode === 'AUTH_TOKEN_NOT_FOUND' && status === 401) {
      try {
        // Attempt to refresh the authentication token
        await APIRefresh.get('/auth/refresh')
        // Retry the original request with the new token
        return APIRefresh(error.config)
      } catch (error) {
        // If token refresh fails, redirect to home page
        window.location.href = '/'
      }
    }

    // For all other errors, reject the promise with the error data
    return Promise.reject({
      ...data,
    })
  },
)

export default API

// NOTE: The code implements an automatic token refresh mechanism when API calls fail due to authentication issues

/* 
The main logic flow works like this:

When any API request fails with status 401 (Unauthorized) and errorCode 'AUTH_TOKEN_NOT_FOUND'
The interceptor automatically tries to get a new token via '/auth/refresh' endpoint
If successful, it retries the original failed request with the new token
If refresh fails, it redirects to home page (likely the login page)
The separate APIRefresh instance is created specifically to handle the refresh token requests, keeping it isolated from the main API instance to avoid 
infinite loops.

This pattern is valuable because:

It handles token expiration gracefully without disrupting user experience
Users don't need to manually log in again when their token expires
It's all automated through the Axios interceptor
It provides a fallback (redirect to home) when refresh fails
The code uses withCredentials: true to ensure cookies are sent with requests, which is where refresh tokens are typically stored securely.
*/
