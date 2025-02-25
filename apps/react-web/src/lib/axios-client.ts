import axios from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL

const options = {
  baseURL,
  withCredentials: true,
  timeout: 10000,
}

const API = axios.create(options)
export const APIRefresh = axios.create(options)

APIRefresh.interceptors.response.use((response) => response)

API.interceptors.response.use(
  (response) => response,
  async (error) => {
    const { data, status, config } = error.response
    /* 
    // NOTE: This segment of code handles the case when there is an error with the authentication token
    to true (line 33). This flag is used to prevent infinite loops when retrying the request. It then tries to refresh the token using the refresh 
    token in the cookie. If the refresh token is valid, the request is retried with the new token (line 35). If the refresh token is invalid, the 
    request is rejected. Check below for the entire flow of the code
    */
    if (config._retry) {
      return Promise.reject(data) // Stop retrying
    }

    if (data.errorCode === 'AUTH_TOKEN_NOT_FOUND' && status === 401) {
      try {
        // Mark the original request to avoid infinite loops
        config._retry = true
        await APIRefresh.get('/auth/refresh')
        return API(config) // Retry the original request with the new token
      } catch (refreshError) {
        // If refresh fails i.e if there's no refresh token in the cookie, reject the promise with the error which bubbles back to useAuth (react-query)
        console.log('Refresh token failed:', refreshError)

        /* 
        Dont use the window to navigate as it will refresh the page, use client side routing instead like <Navigate to="/" replace />
        The problem with this approach is that it will keep refreshing the page and the user will be stuck in a loop. Check below
        */
        // window.location.href = '/'
        return Promise.reject(refreshError) // Ensure the error is rejected
      }
    }

    return Promise.reject(data)
  },
)

export default API

/*
// NOTE: What Was Happening with window.location.href
Even with retry: 0, the infinite loop occurred due to a combination of the interceptor’s behavior and the browser’s navigation. Here’s the sequence:

Initial /session Request:
  useAuth triggers getUserSessionQueryFn, which uses API to call /session.
  No access token exists, so the server returns 401 AUTH_TOKEN_NOT_FOUND.
Interceptor Triggers:
  The interceptor catches the 401, sets config._retry = true, and attempts /auth/refresh.
  No refresh token exists, so /auth/refresh fails with a 401 ACCESS_UNAUTHORIZED, landing in the catch block.
  window.location.href = '/' Executes:
  The catch block logs the error and sets window.location.href = '/', initiating a navigation to /.
  However, this navigation doesn’t immediately stop the JavaScript execution. The interceptor continues to return Promise.reject(refreshError).
Promise Rejection Reaches react-query:
  The rejected Promise propagates back to useQuery.
  Since retry: 0, react-query doesn’t retry, marks the query as failed, and sets isLoading to false with data as undefined.
Navigation Reloads the App:
  Meanwhile, the window.location.href = '/' navigation takes effect, reloading the app or re-rendering the root route.
  On reload, useAuth runs again (because it’s part of AuthRoute or another component that mounts), triggering a new /session request.
  This new request fails again (no token), hits the interceptor, tries /auth/refresh, fails, navigates again, and repeats—creating the loop.
Why the Loop?:
  The loop wasn’t from react-query retries (since retry: 0), but from the app reload/navigation cycle caused by window.location.href.
  Each navigation restarted the app, re-mounted useAuth, and triggered a new API call, bypassing the config._retry check because it’s a fresh request.
*/

/* 
// NOTE: Why config._retry is set to true
1. When the initial API request fails (useAuth() to fetch the session/user details) with a 401 status and 'AUTH_TOKEN_NOT_FOUND' error code, 
the interceptor catches the error.
2. Before attempting to refresh the token, the code checks if config._retry is already set to true.
3. If config._retry is not true, the code sets it to true and proceeds with the refresh token request to fetch a new access token.
4. If the refresh token request succeeds, the original request is retried with the new access token. If the refresh token is invalid, the 
request is rejected which bubbles back to the useAuth (react-query) hook.
5. Now lets say I successsfully refresh the token, the interceptor will retry the original request with the new access token. If now retrying of the
failed request is successful then we return back the response (line 17) but if it fails again, it's caught by the axios response interceptor again 
line (18). Now, config._retry is true, it means the request has already tried to refresh the token, so the code returns the rejection immediately 
(return Promise.reject(data)). This prevents another attempt at refreshing the token.


*/
